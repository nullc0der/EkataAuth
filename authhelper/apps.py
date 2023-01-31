from django.apps import AppConfig


class AuthhelperConfig(AppConfig):
    name = 'authhelper'

    def ready(self) -> None:
        import authhelper.signals
