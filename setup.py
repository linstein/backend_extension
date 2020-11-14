from setuptools import setup

# 这是一个和根目录相关的安装文件的列表，列表中setup.py更具体)

# files = ["things/*"]

setup(name="bktest",
      version="1",
      description="yadda yadda",
      author="linstein",
      author_email="2295285850@qq.com",
      url="whatever",
      # Name the folder where your packages live:
      # (If you have other packages (dirs) or modules (py files) then
      # put them into the package directory - they will be found recursively.)
      packages=['bktest'],
      # 'package' package must contain files (see list above)
      # I called the package 'package' thus cleverly confusing the whole issue...
      # This dict maps the package name =to=> directories
      # It says, package *needs* these files.
      # package_data={'package': files},
      # 'runner' is in the root.
      long_description="""test backend extension""",\
)
