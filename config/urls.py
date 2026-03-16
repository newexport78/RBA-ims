from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

handler404 = 'config.views.page_not_found'
handler500 = 'config.views.server_error'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('accounts.urls')),
    # Admin/User order URLs removed; only 2IC→Employee orders remain.
    path('dashboard/twoic/orders/', include(('orders.urls_twoic', 'orders_twoic'))),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
