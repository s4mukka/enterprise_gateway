from traitlets.config import LoggingConfigurable

class Security(LoggingConfigurable):
    def __init__(self, parent):
        self.parent = parent
