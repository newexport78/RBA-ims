"""Order views: Admin creates orders, assigns to users; list/detail/delete. User: download PDF."""
import hmac
import io
import logging
import os
import re

from django.contrib.auth import get_user_model
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from pypdf import PdfReader, PdfWriter
from pypdf.errors import PdfReadError, PdfStreamError

PAGE_SIZE = 25

from accounts.audit import log_audit_event
from accounts.models import Role
from accounts.rbac import role_required

from .file_validation import sanitize_filename, validate_pdf_upload
from .models import Order, OrderAssignment, AssignmentStatus, ProgressSubmission, UserDocument

User = get_user_model()
logger = logging.getLogger(__name__)


def _employee_pdf_password(user):
    """
    Build PDF open password for an employee:
    last 2 digits of employee_number + last 3 digits of phone + DoB as DDMMYY.
    """
    emp = (user.employee_number or user.username or '')[:]
    digits_emp = re.sub(r'\D', '', emp)
    part_emp = digits_emp[-2:] if len(digits_emp) >= 2 else digits_emp.zfill(2)
    phone = (user.phone or '')[:]
    digits_phone = re.sub(r'\D', '', phone)
    part_phone = digits_phone[-3:] if len(digits_phone) >= 3 else digits_phone.zfill(3)

    part_dob = ''
    if user.date_of_birth:
        part_dob = user.date_of_birth.strftime('%d%m%y')

    return part_emp + part_phone + part_dob


def _employee_download_gate_code(user):
    """
    Web gate only (not the PDF open password): DDMMYY + 1215 + last 2 digits of employee number.
    If date of birth is missing, the DDMMYY part is empty (same digits as 2IC export suffix pattern).
    """
    emp = (user.employee_number or user.username or '')[:]
    digits_emp = re.sub(r'\D', '', emp)
    part_emp = digits_emp[-2:] if len(digits_emp) >= 2 else digits_emp.zfill(2)
    part_dob = ''
    if user.date_of_birth:
        part_dob = user.date_of_birth.strftime('%d%m%y')
    return part_dob + '1215' + part_emp


@require_http_methods(['GET', 'POST'])
@role_required(Role.EMPLOYEE)
def employee_download_gate(request, order_id):
    """
    Employee enters the web access code (DDMMYY + 1215 + last 2 of employee number) before
    the PDF can be opened. The PDF file itself stays encrypted with _employee_pdf_password.
    """
    assignment = get_object_or_404(
        OrderAssignment,
        order_id=order_id,
        user=request.user,
    )
    order = assignment.order
    if not order.pdf_file:
        raise Http404('This order has no PDF.')

    if request.method == 'GET':
        return render(request, 'orders/employee_pdf_gate.html', {'order': order})

    entered = (request.POST.get('code') or '').strip()
    expected = _employee_download_gate_code(request.user)
    if not entered or not hmac.compare_digest(entered, expected):
        messages.error(request, 'Invalid access code. Try again.')
        return render(request, 'orders/employee_pdf_gate.html', {'order': order})

    request.session[f'pdf_gate_ok:{order_id}'] = True
    return redirect('orders:download_order_pdf', order_id=order_id)


def _encrypt_pdf_with_password(source_file, user_password: str):
    """Read PDF from file, encrypt with user_password, return bytes."""
    try:
        reader = PdfReader(source_file)
    except (PdfReadError, PdfStreamError):
        # Stored file is not a valid PDF (e.g. a Word/ZIP file renamed as .pdf)
        raise Http404('This order file is not a valid PDF.')
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(user_password=user_password, algorithm="AES-256")
    buf = io.BytesIO()
    writer.write(buf)
    buf.seek(0)
    return buf.getvalue()


def _employee_watermark_label(user):
    """Text burned into each page for traceability (employee number preferred)."""
    raw = (user.employee_number or user.username or str(user.pk)).strip()
    safe = ''.join(c for c in raw if c.isprintable()).strip()
    return (safe[:64] or str(user.pk))[:64]


def _single_page_watermark_reader(page_width: float, page_height: float, text: str) -> PdfReader:
    """One transparent PDF page with diagonal watermark text, sized to a document page."""
    packet = io.BytesIO()
    c = canvas.Canvas(packet, pagesize=(page_width, page_height))
    c.saveState()
    c.setFillColor(colors.Color(0.5, 0.5, 0.5, alpha=0.28))
    font_size = max(14, min(52, min(page_width, page_height) * 0.065))
    if len(text) > 12:
        font_size = max(12, min(font_size, min(page_width, page_height) * 0.045))
    c.setFont('Helvetica-Bold', font_size)
    c.translate(page_width / 2, page_height / 2)
    c.rotate(35)
    c.drawCentredString(0, 0, text)
    c.restoreState()
    c.save()
    packet.seek(0)
    return PdfReader(packet)


def _encrypt_pdf_with_employee_watermark(source_file, user, user_password: str) -> bytes:
    """Watermark each page with employee number, then AES-encrypt for that employee."""
    try:
        reader = PdfReader(source_file)
    except (PdfReadError, PdfStreamError):
        raise Http404('This order file is not a valid PDF.')
    label = _employee_watermark_label(user)
    writer = PdfWriter()
    for page in reader.pages:
        mb = page.mediabox
        pw = float(mb.right) - float(mb.left)
        ph = float(mb.top) - float(mb.bottom)
        if pw < 1 or ph < 1:
            writer.add_page(page)
            continue
        wm_reader = _single_page_watermark_reader(pw, ph, label)
        page.merge_page(wm_reader.pages[0])
        writer.add_page(page)
    writer.encrypt(user_password=user_password, algorithm="AES-256")
    buf = io.BytesIO()
    writer.write(buf)
    buf.seek(0)
    return buf.getvalue()


def _admin_user_document_queryset(request):
    """UserDocuments sent to this admin (or legacy docs from their own users)."""
    return UserDocument.objects.filter(
        Q(recipient_admin=request.user)
        | (Q(recipient_admin__isnull=True) & Q(user__created_by=request.user))
    ).select_related('user')


@require_GET
@role_required(Role.ADMIN)
def admin_progress_submissions(request):
    """
    List progress submissions for this admin's orders/users.

    Shows submissions where either:
    - the order was created by this admin, or
    - the submitting user was created by this admin (legacy behaviour).
    """
    submissions = (
        ProgressSubmission.objects.filter(
            Q(assignment__order__created_by=request.user)
            | Q(assignment__user__created_by=request.user)
        )
        .select_related('assignment', 'assignment__order', 'assignment__user')
        .order_by('-submitted_at')
    )
    return render(request, 'orders/admin_progress_submissions.html', {'submissions': submissions})


@require_http_methods(['GET', 'POST'])
@role_required(Role.ADMIN)
def admin_user_document_delete(request, document_id):
    """Delete a user document (confirm on GET, delete on POST). Only documents of admin's users."""
    qs = _admin_user_document_queryset(request)
    doc = get_object_or_404(qs, pk=document_id)
    if request.method == 'GET':
        return render(request, 'orders/admin_user_document_confirm_delete.html', {'document': doc})
    file_name = doc.file_name
    if doc.file:
        doc.file.delete(save=False)
    doc.delete()
    messages.success(request, f'Document "{file_name}" has been deleted.')
    return redirect('orders:admin_progress_submissions')


@require_http_methods(['GET'])
@role_required(Role.ADMIN)
def order_list(request):
    """(Legacy) Admin orders view is disabled in this setup."""
    raise Http404()


@require_http_methods(['GET', 'POST'])
@role_required(Role.ADMIN)
def order_create(request):
    """(Legacy) Admin order create is disabled; 2ICs use dashboard/twoic/orders/create/."""
    raise Http404()


@require_http_methods(['GET'])
@role_required(Role.ADMIN)
def order_detail(request, order_id):
    """(Legacy) Admin order detail is disabled; 2ICs use dashboard/twoic/orders/."""
    raise Http404()


@require_http_methods(['GET', 'POST'])
@role_required(Role.ADMIN)
def order_delete(request, order_id):
    """(Legacy) Admin order delete is disabled; 2ICs use dashboard/twoic/orders/."""
    raise Http404()


# ---------- 2IC orders (assign to employees only) ----------


@require_http_methods(['GET'])
@role_required(Role.TWOIC)
def twoic_order_list(request):
    """Orders created by this 2IC."""
    qs = Order.objects.filter(created_by=request.user).prefetch_related('assignments', 'assignments__user')
    paginator = Paginator(qs, PAGE_SIZE)
    page_obj = paginator.get_page(request.GET.get('page', 1))
    return render(request, 'orders/twoic_order_list.html', {'orders': page_obj, 'page_obj': page_obj})


@require_http_methods(['GET', 'POST'])
@role_required(Role.TWOIC)
def twoic_order_create(request):
    """2IC creates order; assign to employees (created by this 2IC) only."""
    my_employees = User.objects.filter(role=Role.EMPLOYEE, created_by=request.user, is_active=True).order_by('employee_number', 'username')
    if request.method == 'GET':
        return render(request, 'orders/twoic_order_form.html', {'my_employees': my_employees, 'selected_ids': [], 'assign_all': False})

    title = (request.POST.get('title') or '').strip()
    description = (request.POST.get('description') or '').strip()
    user_ids = request.POST.getlist('assignees')
    assign_all = request.POST.get('assign_all') == '1'
    pdf_file = request.FILES.get('pdf_file')

    valid_user_ids = set(my_employees.values_list('pk', flat=True))
    if assign_all:
        assignee_ids = list(valid_user_ids)
    else:
        assignee_ids = [int(x) for x in user_ids if x.isdigit() and int(x) in valid_user_ids]

    if not title:
        messages.error(request, 'Title is required.')
        return render(request, 'orders/twoic_order_form.html', {
            'my_employees': my_employees,
            'title': title, 'description': description,
            'selected_ids': assignee_ids,
            'assign_all': assign_all,
        })

    if not assignee_ids:
        messages.error(request, 'Select at least one employee to assign, or check "Send to all employees".')
        return render(request, 'orders/twoic_order_form.html', {
            'my_employees': my_employees,
            'title': title, 'description': description,
            'selected_ids': [],
            'assign_all': False,
        })

    order = Order.objects.create(
        title=title,
        description=description,
        created_by=request.user,
    )
    if pdf_file:
        ok, err = validate_pdf_upload(pdf_file)
        if not ok:
            messages.error(request, err)
            order.delete()
            return render(request, 'orders/twoic_order_form.html', {
                'my_employees': my_employees, 'title': title, 'description': description,
                'selected_ids': assignee_ids, 'assign_all': assign_all,
            })
        try:
            order.pdf_file.save(sanitize_filename(pdf_file.name), pdf_file, save=True)
        except Exception:
            logger.exception(
                "Order PDF upload failed for order_id=%s twoic_id=%s filename=%s",
                order.pk,
                getattr(request.user, "pk", None),
                getattr(pdf_file, "name", ""),
            )
            order.delete()
            messages.error(
                request,
                "PDF upload failed. Please check storage configuration/permissions and try again.",
            )
            return render(request, 'orders/twoic_order_form.html', {
                'my_employees': my_employees, 'title': title, 'description': description,
                'selected_ids': assignee_ids, 'assign_all': assign_all,
            })

    for uid in assignee_ids:
        OrderAssignment.objects.create(order=order, user_id=uid, status=AssignmentStatus.SENT)
    log_audit_event('ORDER_CREATED', request=request, details={'order_id': order.pk, 'title': order.title})
    messages.success(request, f'Order "{order.title}" created and assigned to {len(assignee_ids)} employee(s).')
    return redirect('orders_twoic:twoic_order_detail', order_id=order.pk)


@require_http_methods(['GET'])
@role_required(Role.TWOIC)
def twoic_order_detail(request, order_id):
    """Order detail for 2IC."""
    order = get_object_or_404(Order, pk=order_id, created_by=request.user)
    assignments = order.assignments.select_related('user').all()
    return render(request, 'orders/twoic_order_detail.html', {'order': order, 'assignments': assignments})


@require_http_methods(['GET', 'POST'])
@role_required(Role.TWOIC)
def twoic_order_delete(request, order_id):
    """2IC deletes own order."""
    order = get_object_or_404(Order, pk=order_id, created_by=request.user)
    if request.method == 'GET':
        return render(request, 'orders/twoic_order_confirm_delete.html', {'order': order})
    order_title, order_pk = order.title, order.pk
    order.delete()
    log_audit_event('ORDER_DELETED', request=request, details={'order_id': order_pk, 'title': order_title})
    messages.success(request, f'Order "{order_title}" has been deleted.')
    return redirect('orders_twoic:twoic_order_list')


@require_GET
@role_required(Role.USER, Role.EMPLOYEE)
def download_order_pdf(request, order_id):
    """User/Employee downloads the order PDF. Only if assigned. Marks as viewed. For employees, each page is watermarked with employee number, then encrypted (PDF password = last 2 of employee id + last 3 of phone + DoB DDMMYY)."""
    assignment = get_object_or_404(
        OrderAssignment,
        order_id=order_id,
        user=request.user,
    )
    order = assignment.order
    if not order.pdf_file:
        raise Http404('This order has no PDF.')
    if not assignment.viewed_at:
        assignment.viewed_at = timezone.now()
        assignment.status = AssignmentStatus.VIEWED
        assignment.save(update_fields=['viewed_at', 'status'])
    log_audit_event('ORDER_DOWNLOADED', request=request, details={'order_id': order.pk, 'title': order.title})

    filename = os.path.basename(order.pdf_file.name) or 'order.pdf'

    if request.user.role == Role.EMPLOYEE:
        if not request.session.get(f'pdf_gate_ok:{order_id}'):
            return redirect('orders:employee_download_gate', order_id=order_id)
        request.session.pop(f'pdf_gate_ok:{order_id}', None)
        password = _employee_pdf_password(request.user)
        with order.pdf_file.open('rb') as fh:
            pdf_bytes = _encrypt_pdf_with_employee_watermark(fh, request.user, password)
        response = HttpResponse(pdf_bytes, content_type='application/pdf')
        response['Content-Disposition'] = f'inline; filename="{filename}"'
        return response

    return FileResponse(
        order.pdf_file.open('rb'),
        as_attachment=True,
        filename=filename,
    )


@require_http_methods(['GET', 'POST'])
@role_required(Role.USER)
def submit_progress(request, order_id):
    """User submits progress for an order: notes + optional progress PDF. Updates assignment status to Completed."""
    assignment = get_object_or_404(
        OrderAssignment,
        order_id=order_id,
        user=request.user,
    )
    order = assignment.order
    if request.method == 'GET':
        return render(request, 'orders/submit_progress.html', {'assignment': assignment, 'order': order})

    notes = (request.POST.get('notes') or '').strip()
    progress_file = request.FILES.get('progress_file')

    if not notes and not progress_file:
        messages.error(request, 'Add notes and/or upload a progress PDF.')
        return render(request, 'orders/submit_progress.html', {'assignment': assignment, 'order': order, 'notes': notes})

    if progress_file:
        ok, err = validate_pdf_upload(progress_file)
        if not ok:
            messages.error(request, err)
            return render(request, 'orders/submit_progress.html', {'assignment': assignment, 'order': order, 'notes': notes})
        progress_file.name = sanitize_filename(progress_file.name)

    kwargs = {'assignment': assignment, 'notes': notes}
    if progress_file:
        kwargs['file'] = progress_file
    ProgressSubmission.objects.create(**kwargs)
    assignment.status = AssignmentStatus.COMPLETED
    assignment.save(update_fields=['status'])
    log_audit_event('PROGRESS_UPLOADED', request=request, details={'order_id': order.pk, 'assignment_id': assignment.pk})
    messages.success(request, 'Your progress has been submitted.')
    return redirect('accounts:user_dashboard')


@require_GET
@role_required(Role.USER)
def my_submissions(request):
    """List this user's progress submissions (history) — per order."""
    submissions = (
        ProgressSubmission.objects.filter(assignment__user=request.user)
        .select_related('assignment', 'assignment__order')
        .order_by('-submitted_at')
    )
    return render(request, 'orders/my_submissions.html', {'submissions': submissions})


# ---------- Independent user document upload (not tied to any order) ----------


@require_http_methods(['GET', 'POST'])
@role_required(Role.USER)
def upload_document(request):
    """User uploads a PDF document independently — no order. Like order from admin, but user-uploaded."""
    admins = User.objects.filter(role=Role.ADMIN, is_active=True).order_by('username')
    if request.method == 'GET':
        return render(request, 'orders/upload_document.html', {
            'admins': admins,
            'selected_admin_ids': [],
            'assign_all': False,
        })

    notes = (request.POST.get('notes') or '').strip()
    doc_file = request.FILES.get('file')
    admin_ids = request.POST.getlist('admin_ids')
    assign_all = request.POST.get('assign_all') == '1'

    valid_admin_ids = set(admins.values_list('pk', flat=True))
    if assign_all:
        selected_ids = list(valid_admin_ids)
    else:
        selected_ids = [int(x) for x in admin_ids if x.isdigit() and int(x) in valid_admin_ids]

    if not selected_ids:
        messages.error(request, 'Please choose at least one admin to send this document to, or check \"Send to all admins\".')
        return render(request, 'orders/upload_document.html', {
            'notes': notes,
            'admins': admins,
            'selected_admin_ids': selected_ids,
            'assign_all': assign_all,
        })

    if not doc_file:
        messages.error(request, 'Please select a PDF file.')
        return render(request, 'orders/upload_document.html', {
            'notes': notes,
            'admins': admins,
            'selected_admin_ids': selected_ids,
            'assign_all': assign_all,
        })

    ok, err = validate_pdf_upload(doc_file)
    if not ok:
        messages.error(request, err)
        return render(request, 'orders/upload_document.html', {
            'notes': notes,
            'admins': admins,
            'selected_admin_ids': selected_ids,
            'assign_all': assign_all,
        })
    doc_file.name = sanitize_filename(doc_file.name)
    selected_admins = list(admins.filter(pk__in=selected_ids))

    created_ids = []
    first_admin, *other_admins = selected_admins
    first_doc = UserDocument.objects.create(
        user=request.user,
        file=doc_file,
        notes=notes,
        recipient_admin=first_admin,
    )
    created_ids.append(first_doc.pk)
    for admin in other_admins:
        clone = UserDocument.objects.create(
            user=request.user,
            file=first_doc.file.name,
            notes=notes,
            recipient_admin=admin,
        )
        created_ids.append(clone.pk)

    log_audit_event(
        'USER_DOCUMENT_UPLOADED',
        request=request,
        details={
            'document_ids': created_ids,
            'recipient_admin_ids': [a.pk for a in selected_admins],
            'assign_all': assign_all,
        },
    )
    messages.success(request, 'Your document has been uploaded.')
    return redirect('accounts:user_my_documents')


@require_http_methods(['GET', 'POST'])
@role_required(Role.USER)
def user_document_delete(request, document_id):
    """Delete own document (confirm on GET, delete on POST)."""
    doc = get_object_or_404(UserDocument, pk=document_id, user=request.user)
    if request.method == 'GET':
        return render(request, 'orders/user_document_confirm_delete.html', {'document': doc})
    file_name = doc.file_name
    if doc.file:
        doc.file.delete(save=False)
    doc.delete()
    messages.success(request, f'Document "{file_name}" has been deleted.')
    return redirect('accounts:user_my_documents')


@require_GET
@role_required(Role.USER)
def my_documents(request):
    """List this user's independent uploaded documents (not linked to orders)."""
    documents = UserDocument.objects.filter(user=request.user).order_by('-uploaded_at')
    return render(request, 'orders/my_documents.html', {'documents': documents})
