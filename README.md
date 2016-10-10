under developing

This program is Junos ACL checker. It validates JUNOS ACL written in csv file.
In general, JUNOS evaluates ACL from lower term. If lower prefix is allocated lower term, higher term is not evaluated even prefer prefix is allocate.
Hence, operater must consider prefer prefix into appropriate term.

This program evaluates prefix, protocol, port and reorder them instead of operator.
Also, if prefix and port are not valid, this program return which line is not valid.