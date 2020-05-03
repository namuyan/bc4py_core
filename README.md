bc4py-core
====
This repository is bc4py core program.

Install
----
Python3.6+
```commandline
pip install bc4py-core
```

build
----
```shell script
curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly
pip install setuptools-rust
git clone git+https://github.com/namuyan/bc4py_core
cd bc4py_core
python setup.py bdist_wheel
# check dist
```

fmt
----
* format `cargo fmt`
* check `cargo fmt -- --check`

Licence
----
MIT

Author
----
[@namuyan_mine](https://twitter.com/namuyan_mine)
