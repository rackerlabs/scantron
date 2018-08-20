from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

from django_scantron.models import ScheduledScan


@login_required(login_url='login')
def retrieve_scan_file(request, id):
    # Lookup result_file_base_name based of scan ID.
    result_file_base_name = ScheduledScan.objects.get(id=id).result_file_base_name
    file_extension = 'nmap'
    scan_file = '{}.{}'.format(result_file_base_name, file_extension)

    # Serve file using nginx X-Accel-Redirect.
    # https://wellfire.co/learn/nginx-django-x-accel-redirects/
    response = HttpResponse()
    response['Content-Type'] = 'text/plain'
    response['Content-Disposition'] = 'inline; filename={}'.format(scan_file)
    response['X-Accel-Redirect'] = '/protected/complete/{}'.format(scan_file)
    return response
