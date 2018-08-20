from django import template

register = template.Library()


@register.simple_tag
def scantron_version():
    from django_scantron import __version__
    return 'version ' + __version__
