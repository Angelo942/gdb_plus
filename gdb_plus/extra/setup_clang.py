import glob
from importlib.metadata import version
import clang.cindex

def get_clang_lib_path():
    # Step 1: Get Python clang package version
    try:
        clang_version = version("clang")
    except Exception as e:
        raise RuntimeError(f"Could not determine clang version from Python package: {e}")

    major_version = clang_version.split('.')[0]

    possible_patterns = [
        f"/usr/lib*/llvm-{major_version}/lib/libclang*.so",
        f"/usr/lib*/libclang.so.{major_version}*",
        f"/usr/lib*/libclang-cpp.so.{major_version}*",
        f"/usr/local/lib*/libclang.so.{major_version}*"
    ]

    for pattern in possible_patterns:
        matches = glob.glob(pattern)
        if matches:
            # print("Found candidate libclang:", matches[0])
            return matches[0]

    # We can not find it, but is it because the user has an older version of libclang ?
    for older_version in range(int(major_version)):
        possible_patterns = [
            f"/usr/lib*/llvm-{older_version}/lib/libclang*.so",
            f"/usr/lib*/libclang.so.{older_version}*",
            f"/usr/lib*/libclang-cpp.so.{older_version}*",
            f"/usr/local/lib*/libclang.so.{older_version}*"
        ]

        for pattern in possible_patterns:
            matches = glob.glob(pattern)
            if matches:
                raise FileNotFoundError(f"Could not find a matching libclang.so for version {major_version}. You may have to downgrade clang to {older_version}.x.x")

    raise FileNotFoundError(f"Could not find a matching libclang.so for version {major_version}. Do you have libclang-dev installed ?")


def load_clang():
    if clang.cindex.Config.library_file is None:
            libclang_path = get_clang_lib_path()
            clang.cindex.Config.set_library_file(libclang_path)