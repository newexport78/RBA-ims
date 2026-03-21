from django.urls import path

from . import views

app_name = 'orders'

urlpatterns = [
    path('', views.order_list, name='order_list'),
    path('progress/', views.admin_progress_submissions, name='admin_progress_submissions'),
    path('progress/<int:document_id>/delete/', views.admin_user_document_delete, name='admin_user_document_delete'),
    path('create/', views.order_create, name='order_create'),
    path('<int:order_id>/', views.order_detail, name='order_detail'),
    path('<int:order_id>/delete/', views.order_delete, name='order_delete'),
    path('download/<int:order_id>/', views.download_order_pdf, name='download_order_pdf'),
    path('download/<int:order_id>/gate/', views.employee_download_gate, name='employee_download_gate'),
]
