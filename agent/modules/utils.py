import datetime


def get_current_time():
    """Retrieve a Django compliant pre-formated datetimestamp."""

    now_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return now_datetime
