
rule ReverseShell
{
    strings:
        $a = "nc -e"
        $b = "bash -i >& /dev/tcp/"
    condition:
        any of them
}
