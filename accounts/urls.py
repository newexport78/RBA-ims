from django.urls import path

from . import views
from orders.views import download_order_pdf, my_documents, my_submissions, submit_progress, upload_document, user_document_delete

app_name = 'accounts'

urlpatterns = [
    path('', views.login_redirect),
    path('login/', views.login_view, name='login'),
    path('otp/', views.otp_verify_view, name='otp_verify'),
    path('redirect/', views.login_redirect, name='login_redirect'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/superadmin/', views.superadmin_dashboard, name='superadmin_dashboard'),
    path('dashboard/superadmin/users/', views.superadmin_user_list, name='superadmin_user_list'),
    path('dashboard/superadmin/users/create/', views.superadmin_user_create, name='superadmin_user_create'),
    path('dashboard/superadmin/users/<int:user_id>/approve/', views.superadmin_user_approve, name='superadmin_user_approve'),
    path('dashboard/superadmin/users/<int:user_id>/delete/', views.superadmin_user_delete, name='superadmin_user_delete'),
    path('dashboard/superadmin/users/<int:user_id>/reset-password/', views.superadmin_user_reset_password, name='superadmin_user_reset_password'),
    path('dashboard/superadmin/devices/', views.superadmin_device_list, name='superadmin_device_list'),
    path('dashboard/superadmin/devices/<int:device_id>/approve/', views.superadmin_device_approve, name='superadmin_device_approve'),
    path('dashboard/superadmin/devices/<int:device_id>/block/', views.superadmin_device_block, name='superadmin_device_block'),
    path('dashboard/superadmin/audit/', views.superadmin_audit_log, name='superadmin_audit_log'),
    path('dashboard/superadmin/settings/', views.superadmin_settings, name='superadmin_settings'),
    path('dashboard/superadmin/profile/', views.superadmin_profile, name='superadmin_profile'),
    path('account/change-password/', views.change_password_view, name='change_password'),
    path('dashboard/twoic/', views.twoic_dashboard, name='twoic_dashboard'),
    path('dashboard/twoic/employees/', views.twoic_my_employees, name='twoic_my_employees'),
    path('dashboard/twoic/employees/create/', views.twoic_employee_create, name='twoic_employee_create'),
    path('dashboard/twoic/profile/', views.twoic_profile, name='twoic_profile'),
    path('dashboard/twoic/export-employees-csv/', views.twoic_export_employees_csv, name='twoic_export_employees_csv'),
    path('dashboard/employee/', views.employee_dashboard, name='employee_dashboard'),
    path('dashboard/employee/profile/', views.employee_profile, name='employee_profile'),
]
