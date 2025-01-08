from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    # path("cycles/", views.cycles, name="cycles"),
    path("runningdata/", views.runningdata, name="runningdata"),
    path("memsamples/", views.get_mem_samples, name="memsamples"),
    path("activepages/", views.get_active_pages, name="activepages"),
    path('functionDetails/<str:function_name>/', views.function_details, name='function_details'),
    path('datarecord/<str:file_path>/', views.data_record, name='data_record'),
    path("file_upload/", views.file_upload, name="file_upload"),
]