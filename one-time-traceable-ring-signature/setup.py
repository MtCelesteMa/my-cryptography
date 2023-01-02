from setuptools.command.build_ext import build_ext
from setuptools import Extension, setup


class custom_build_ext(build_ext):
    def build_extensions(self):
        # Override the compiler executables. Importantly, this
        # removes the "default" compiler flags that would
        # otherwise get passed on to to the compiler, i.e.,
        # distutils.sysconfig.get_var("CFLAGS").
        self.compiler.set_executable("compiler_so", "gcc")
        self.compiler.set_executable("compiler_cxx", "gcc")
        self.compiler.set_executable("linker_so", "gcc")
        build_ext.build_extensions(self)

[
setup(
    name="spam",
    ext_modules=[
        Extension(
            "spam", 
            sources=["main.c", "sha2.c", "ring.c"],
            extra_compile_args=["-g", "-lssl", "-lcrypto"],
            extra_link_args=["-g", "-lssl", "-lcrypto"]
        )
    ],
    zip_safe=False,
    cmdclass={"build_ext": custom_build_ext}
)]
