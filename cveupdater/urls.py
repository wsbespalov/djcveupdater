
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView


# Admin route

urlpatterns = [
    path('admin/', admin.site.urls),
]

# Media
from django.conf import settings
from django.conf.urls.static import static
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Index redirect

urlpatterns += [
    path('', RedirectView.as_view(url='/main/', permanent=True))
]

# Stats routes

urlpatterns += [
    path('stats/', include('stats.urls')),
]

# Main app routes

urlpatterns += [
    path('main/', include('main.urls')),
]

# CPE

urlpatterns += [
    path('cpe/', include('updater_cpe.urls'))
]

# CWE

urlpatterns += [
    path('cwe/', include('updater_cwe.urls'))
]