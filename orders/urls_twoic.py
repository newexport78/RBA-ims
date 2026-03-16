from django.urls import path

from . import views

app_name = 'orders_twoic'

urlpatterns = [
    path('', views.twoic_order_list, name='twoic_order_list'),
    path('create/', views.twoic_order_create, name='twoic_order_create'),
    path('<int:order_id>/', views.twoic_order_detail, name='twoic_order_detail'),
    path('<int:order_id>/delete/', views.twoic_order_delete, name='twoic_order_delete'),
]
