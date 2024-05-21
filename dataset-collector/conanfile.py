from conans import ConanFile, tools

class DatasetCollectorConan(ConanFile):
    name = "DatasetCollector"
    version = "0.1"
    settings = None
    description = "Dataset collector"
    url = "None"
    license = "None"
    author = "None"
    topics = None

    def package(self):
        self.copy("*")

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
