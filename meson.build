project(
  'flamethrower',
  'cpp', 'c',
  version: '0.12',
  meson_version: '>= 1.3.0',
  default_options: ['cpp_std=c++23,c++20', 'c_std=c23,c17', 'warning_level=3'],
)

# libraries:

libuv = dependency('libuv')
ldns = dependency('ldns')
gnutls = dependency('gnutls')

nghttp2 = dependency('libnghttp2', 'nghttp2', required: get_option('doh'))

# bundled libraries

uvw = dependency('uvw', required: not get_option('bundles'))

if not uvw.found()
uvw_sources = files(
  '3rd/uvw/src/async.cpp',
  '3rd/uvw/src/check.cpp',
  '3rd/uvw/src/dns.cpp',
  '3rd/uvw/src/emitter.cpp',
  '3rd/uvw/src/fs.cpp',
  '3rd/uvw/src/fs_event.cpp',
  '3rd/uvw/src/fs_poll.cpp',
  '3rd/uvw/src/idle.cpp',
  '3rd/uvw/src/lib.cpp',
  '3rd/uvw/src/loop.cpp',
  '3rd/uvw/src/pipe.cpp',
  '3rd/uvw/src/poll.cpp',
  '3rd/uvw/src/prepare.cpp',
  '3rd/uvw/src/process.cpp',
  '3rd/uvw/src/signal.cpp',
  '3rd/uvw/src/stream.cpp',
  '3rd/uvw/src/tcp.cpp',
  '3rd/uvw/src/thread.cpp',
  '3rd/uvw/src/timer.cpp',
  '3rd/uvw/src/tty.cpp',
  '3rd/uvw/src/udp.cpp',
  '3rd/uvw/src/util.cpp',
  '3rd/uvw/src/work.cpp',
)

uvw_includes = include_directories(
  '3rd/uvw/include',
)

uvw_library = static_library(
  'uvw',
  uvw_sources,
  cpp_args: ['-DUVW_AS_LIB', '-iquote', meson.current_source_dir() / '3rd/uvw/include/uvw'],
  dependencies: [libuv],
)

uvw = declare_dependency(
  link_with: uvw_library,
  compile_args: ['-DUVW_AS_LIB', '-iquote', meson.current_source_dir() / '3rd/uvw/include/uvw'],
  include_directories: uvw_includes,
)
endif

json = dependency('json', 'nlohmann_json', required: not get_option('bundles'))

if not json.found()
json = declare_dependency(
  include_directories: include_directories('3rd/json/include'),
)
endif

httplib = dependency('cpp-httplib', 'httplib', required: not get_option('bundles'))

if not httplib.found()
httplib = declare_dependency(
  include_directories: include_directories('3rd/cpp-httplib/include'),
)
endif

urlparse_sources = files(
  '3rd/urlparse/src/urlparse.c',
)

urlparse_includes = include_directories(
  '3rd/urlparse/include',
)

urlparse_library = static_library(
  'urlparse',
  urlparse_sources,
  include_directories: urlparse_includes,
)

urlparse = declare_dependency(
  link_with: [urlparse_library],
  include_directories: urlparse_includes,
)

base64_sources = files(
  '3rd/cpp-base64/src/base64.cpp',
)

base64_includes = include_directories(
  '3rd/cpp-base64/include',
)

base64_library = static_library(
  'base64',
  base64_sources,
  include_directories: base64_includes,
)

base64 = declare_dependency(
  link_with: [base64_library],
  include_directories: base64_includes,
)

docopt = dependency('docopt', required: not get_option('bundles'))

if not docopt.found()
docopt_includes = include_directories(
  '3rd/docopt.cpp/include',
)

docopt_sources = files(
  '3rd/docopt.cpp/src/docopt.cpp',
)

docopt_library = static_library(
  'docopt',
  docopt_sources,
  include_directories: docopt_includes,
)

docopt = declare_dependency(
  link_with: [docopt_library],
  include_directories: docopt_includes,
)
endif

# x

flame_sources = files(
  'flame/addr.cpp',
  'flame/metrics.cpp',
  'flame/metrics.h',
  'flame/query.cpp',
  'flame/query.h',
  'flame/target.h',
  'flame/trafgen.cpp',
  'flame/trafgen.h',
  'flame/tcpsession.cpp',
  'flame/tcpsession.h',
  'flame/tcptlssession.cpp',
  'flame/tcptlssession.h',
  'flame/utils.cpp',
  'flame/utils.h',
  'flame/main.cpp',
)

flame_deps = [
  libuv,
  uvw,
  docopt,
  json,
  httplib,
  urlparse,
  gnutls,
  ldns,
  base64,
]

flame_args = [
  '-DHAVE_STDBOOL_H', # workaround for ldns re-defining bool type
]

if get_option('doh')
  flame_sources += [
    'flame/http.h',
    'flame/httpssession.cpp',
    'flame/httpssession.h',
  ]
  flame_args += [
    '-DDOH_ENABLE'
  ]
  flame_deps += [
    nghttp2,
  ]
endif

flame = executable(
  'flame',
  flame_sources,
  dependencies: flame_deps,
  cpp_args: flame_args,
  include_directories: include_directories('flame'),
  install: true,
)
