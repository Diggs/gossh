# Gossh (go-ssh)

[![GoDoc](https://godoc.org/github.com/Diggs/gossh?status.svg)](https://godoc.org/github.com/Diggs/gossh)

Gossh provides a simple set of wrapper functions for interacting with remote
servers over SSH.

Below is a sample of the provided functions - see GoDoc for comprehensive docs:

`CreateSSHClient` - Creates an SSH client using configurable timeouts and deadlines. Keys can be provided inline as well as being automatically sourced from the local SSH agent.

`RunRemoteCommand` - Runs a command on a remote server using configurable timeouts and deadlines.

`RunLocalCommand` - Runs a command on the local server (by shelling out, not via SSH).

`CopyFileToServer` - Copies a file from the local server to a remote server using SCP over SSH.

`CopyFileStreamToServer` - Copies a file stream from the local server to a remote server using SCP over SSH.

`CopyFileFromServer` - Copies a file from a remote server to the local server using SCP over SSH.
