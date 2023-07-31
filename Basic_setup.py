#setting.py
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')


TEMPLATES = [
    {
        ....
        "DIRS": [TEMPLATES_DIR,],
        ....
            ],
        },
    },
]

TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
MEDIA_DIR = os.path.join(BASE_DIR, 'media')

STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'

# Extra places for collectstatic to find static files.
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),
)
MEDIA_URL = '/media/'

MEDIA_ROOT = MEDIA_DIR


#urls.py (Main Project)
urlpatterns = [
    path('admin/', admin.site.urls),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

#Create Folder
1. media
2. static
3. templates
