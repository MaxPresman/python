import sys


def get_python_version():
    if type(sys.version_info) is tuple:
        return 2
    else:
        if sys.version_info.major == 2:
            return 2
        else:
            return 3


def get_data_for_user(data):
    try:
        if 'message' in data and 'payload' in data:
            return {'message': data['message'], 'payload': data['payload']}
        else:
            return data
    except TypeError:
        return data


class EmptyLock():
    def __init__(self):
        pass

    def __enter__(self):
        pass

    def __exit__(self, a, b, c):
        pass
