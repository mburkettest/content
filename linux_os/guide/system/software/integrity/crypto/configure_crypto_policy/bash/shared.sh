# platform = multi_platform_all
# reboot = false
# strategy = enable
# complexity = low
# disruption = low

{{{ bash_instantiate_variables("var_system_crypto_policy") }}}

{{% if product == "sle15" %}}
{{{ bash_package_install("crypto-policies-scripts") }}}
{{% endif %}}

stderr_of_call=$(update-crypto-policies --set ${var_system_crypto_policy} 2>&1 > /dev/null)
rc=$?

if test "$rc" = 127; then
	echo "$stderr_of_call" >&2
	echo "Make sure that the script is installed on the remediated system." >&2
	echo "See output of the 'dnf provides update-crypto-policies' command" >&2
	echo "to see what package to (re)install" >&2

	false  # end with an error code
elif test "$rc" != 0; then
	echo "Error invoking the update-crypto-policies script: $stderr_of_call" >&2
	false  # end with an error code
fi
