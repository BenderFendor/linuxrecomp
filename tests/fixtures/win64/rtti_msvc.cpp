// MSVC-ABI polymorphic classes, so the image carries the x64 RTTI layout that
// tools/cpp/rtti.py parses: TypeDescriptor (".?AV<name>@@"), a
// CompleteObjectLocator whose signature reads 1, and pointer fields stored as
// 4-byte image-relative offsets instead of absolute VAs.
//
// Built by scripts/build-win64-fixtures.sh with
//   clang --target=x86_64-pc-windows-msvc -c ...
//   lld-link /entry:mainCRTStartup /nodefaultlib ...
// which is what makes the *MSVC* ABI available on a Linux host with no Windows
// SDK install. MinGW cannot produce this fixture: GCC emits Itanium RTTI, which
// has a different record layout and would not exercise the parser at all.
//
// No includes and no CRT on purpose. The optimizer cannot see through `sink`,
// so the vtables and their RTTI records survive into the image.

struct Base {
    virtual ~Base();
    virtual int value() const;
    int base_pad;
};

struct Derived : Base {
    ~Derived() override;
    int value() const override;
    virtual int extra();
    int derived_pad;
};

Base::~Base() {}
int Base::value() const { return 1; }
Derived::~Derived() {}
int Derived::value() const { return 2; }
int Derived::extra() { return 3; }

static Derived *volatile sink;

extern "C" __declspec(dllexport) int mainCRTStartup(void) {
    Derived d;
    sink = &d;
    return sink->value() + sink->extra();
}
