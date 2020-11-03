from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

from django_scantron.models import ScheduledScan

from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import IsAdminUser, IsAuthenticated


@api_view(http_method_names=["GET"])
@authentication_classes((SessionAuthentication, TokenAuthentication,))
@permission_classes((IsAdminUser, IsAuthenticated))
@login_required(login_url="login")
def retrieve_scan_file(request, id):
    # Lookup result_file_base_name based of scan ID.
    requested_scan = ScheduledScan.objects.get(id=id)

    # Extract file_type from ?file_type query parameter.
    file_type = request.GET.get("file_type", "")

    # Pooled scan.
    if file_type == "pooled":
        scan_file = requested_scan.pooled_scan_result_file_base_name
    else:
        result_file_base_name = requested_scan.result_file_base_name
        scan_file = f"{result_file_base_name}.{file_type}"

    # Serve file using nginx X-Accel-Redirect.
    # https://wellfire.co/learn/nginx-django-x-accel-redirects/
    response = HttpResponse()
    response["Content-Type"] = "text/plain"
    response["Content-Disposition"] = f"inline; filename={scan_file}"
    response["X-Accel-Redirect"] = f"/protected/complete/{scan_file}"

    return response
