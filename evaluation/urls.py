from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    # path("cycles/", views.cycles, name="cycles"),
    path("runningdata/", views.runningdata, name="runningdata"),
    path("memsamples/", views.get_mem_samples, name="memsamples"),
]