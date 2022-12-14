if [ -x "%{_sbindir}/semodule" ]; then
	%{_sbindir}/semodule -n -s targeted -r JICMP6 2> /dev/null
	%selinux_modules_install -s targeted %{_datadir}/selinux/packages/JICMP6.pp.bz2
fi
