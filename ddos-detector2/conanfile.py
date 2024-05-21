from conans import ConanFile, tools

class DDoSDetector2Conan(ConanFile):
    name = "DDoSDetector2"
    version = "0.1"
    settings = None
    description = "DDoS Detector 2"
    url = "None"
    license = "None"
    author = "None"
    topics = None

    def package(self):
        self.copy("*")

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
