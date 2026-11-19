contrib_plugins = ['bbv', 'cache', 'cflow', 'drcov', 'execlog', 'hotblocks',
                   'hotpages', 'howvec', 'hwprofile', 'ips', 'stoptrigger']

# Plugins with extra dependencies
contrib_plugins_zstd = ['tracertl']
if host_os != 'windows'
  # lockstep uses socket.h
  contrib_plugins += 'lockstep'
endif

t = []
if get_option('plugins')
  foreach i : contrib_plugins
    plugin_srcs = files(i + '.c')
    if i == 'stoptrigger'
      plugin_srcs += files('plugin_icount_range.c')
    endif
    if host_os == 'windows'
      t += shared_module(i, plugin_srcs + 'win32_linker.c',
                        include_directories: '../../include/qemu',
                        link_depends: [win32_qemu_plugin_api_lib],
                        link_args: win32_qemu_plugin_api_link_flags,
                        dependencies: glib)
    else
      t += shared_module(i, plugin_srcs,
                        include_directories: '../../include/qemu',
                        dependencies: glib)
    endif
  endforeach
endif
# Build plugins that depend on zstd
if get_option('plugins') and zstd.found()
  foreach i : contrib_plugins_zstd
    plugin_srcs = files(i + '.c')
    if i == 'tracertl'
      plugin_srcs += files('tracertl_guest_branch.c',
                           'plugin_icount_range.c',
                           'tracertl_runtime_helpers.c',
                           '../../plugins/tracertl_rv_helpers.c')
    endif
    if host_os == 'windows'
      t += shared_module(i, plugin_srcs + 'win32_linker.c',
                        include_directories: '../../include/qemu',
                        link_depends: [win32_qemu_plugin_api_lib],
                        link_args: win32_qemu_plugin_api_link_flags,
                        dependencies: [glib, zstd])
    else
      t += shared_module(i, plugin_srcs,
                        include_directories: '../../include/qemu',
                        dependencies: [glib, zstd])
    endif
  endforeach
endif

if t.length() > 0
  alias_target('contrib-plugins', t)
else
  run_target('contrib-plugins', command: [python, '-c', ''])
endif

plugin_modules += t
