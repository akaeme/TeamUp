import configparser

class Parser(configparser.ConfigParser):
    def as_dict(self):
        d = dict(self._sections)
        for k in d:
            d[k] = dict(self._defaults, **d[k])
            d[k].pop('__name__', None)
        return d

class Configuration():
    def __init__(self, filename):
        self.parser = Parser()
        self.service_config = {}
        try:
            self.parser.read(filename)
            self.services = self.parser.sections()
        except (FileNotFoundError, KeyError):
            pass
        for service in self.services:
            service_ = {key.upper(): value for key, value in self.parser.items(service)}
            self.service_config[service] = service_