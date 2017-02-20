package gossh

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	// DefaultSSHPort can conveniently be passed as the port argument to functions
	// in this package.
	DefaultSSHPort uint32 = 22
	// DefaultSSHConnectionTimeout can conveniently be passed as the connection
	// timeout argument to functions in this package.
	DefaultSSHConnectionTimeout = time.Second * 30
)

var (
	// Now can be overridden to supply a custom clock. Useful for tests.
	Now = time.Now
	// SSHAuthSockEnvVarName contains the name of the environment variable that
	// points to the local SSH agent's unix socket.
	SSHAuthSockEnvVarName = "SSH_AUTH_SOCK"
)

// makeSSHSigners creates a set of ssh signers using both the supplied privateKeys
// (if any) as well as connecting to the local ssh agent (if available) and using
// its keys.
func makeSSHSigners(privateKeys ...[]byte) ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, key := range privateKeys {
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("Error parsing private key (len %d) for SSH "+
				"connection: %s", len(key), err)
		}
		signers = append(signers, signer)
	}
	// http://stackoverflow.com/questions/24437809/connect-to-a-server-using-ssh-and-a-pem-key-with-golang
	agentSocket := os.Getenv(SSHAuthSockEnvVarName)
	if agentSocket == "" {
		return signers, nil
	}
	sock, err := net.Dial("unix", agentSocket)
	if err != nil {
		return nil, fmt.Errorf("Error dialing local SSH agent: %s", err)
	}
	agent := agent.NewClient(sock)
	agentSigners, err := agent.Signers()
	if err != nil {
		return nil, fmt.Errorf("Error making signers from local SSH agent: %s", err)
	}
	signers = append(signers, agentSigners...)
	return signers, nil
}

// CreateSSHClient creates an SSH client that is configured to use the local
// SSH agent and any specified private keys to facilitate authentication.
func CreateSSHClient(
	user string,
	host string,
	port uint32,
	connectionTimeout time.Duration,
	absoluteDeadline time.Time,
	privateKeys ...[]byte) (*ssh.Client, net.Conn, error) {
	if connectionTimeout <= 0 {
		connectionTimeout = DefaultSSHConnectionTimeout
	}
	signers, err := makeSSHSigners(privateKeys...)
	if err != nil {
		return nil, nil, fmt.Errorf("Error making SSH signers: %s", err)
	}
	address := fmt.Sprintf("%s:%d", host, port)
	authMethods := []ssh.AuthMethod{ssh.PublicKeys(signers...)}
	config := &ssh.ClientConfig{
		User: user,
		Auth: authMethods,
	}
	config.SetDefaults()
	conn, err := net.DialTimeout("tcp", address, connectionTimeout)
	if err != nil {
		return nil, nil, err
	}
	err = conn.SetDeadline(absoluteDeadline)
	if err != nil {
		return nil, nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		return nil, nil, err
	}
	return ssh.NewClient(c, chans, reqs), conn, nil
}

// scanOutput reads lines from pipe and pumps them to receiver. Once all lines
// have been read, or an error is encountered, result chan is sent the error
// or nil.
func scanOutput(
	pipe *io.Reader,
	receiver chan string,
	result chan error,
	absoluteDeadline time.Time,
	idleTimeout time.Duration,
	connection net.Conn) {
	var (
		err             error
		nextIdleTimeout time.Time
		scanner         = bufio.NewScanner(*pipe)
	)
	for {
		if ok := scanner.Scan(); !ok {
			if scanner.Err() != nil {
				result <- fmt.Errorf("Error scanning output: %s", scanner.Err())
			} else {
				result <- nil // nothing more to read
			}
			break
		}
		receiver <- scanner.Text()
		nextIdleTimeout = Now().Add(idleTimeout)
		if nextIdleTimeout.Before(absoluteDeadline) {
			err = connection.SetDeadline(nextIdleTimeout)
		} else {
			err = connection.SetDeadline(absoluteDeadline)
		}
		if err != nil {
			result <- fmt.Errorf("Error setting deadline: %s", err)
			break
		}
	}
}

// RunRemoteCommand runs command on host:port as user. stdOutAndErr will be passed
// a multiplexed stream containing stdout and stderr from the command. This chan
// MUST be drained or command will deadlock. stdOutAndErr chan will be closed
// once all data is read.
// connectionTimeout is the maximum amount of time to wait for the TCP connection
// to establish.
// absoluteDeadline is the absolute time after which all i/o operations will fail
// with timeout errors.
// idleTimeout is the maximum amount of time to wait for activity (e.g. receiving
// a line on stdout) after which all i/o operations will fail with timeout errors.
// (non-zero exit code) then an error will be returned.
// If an error occurs running the command, or the command fails, an error will
// be returned, otherwise nil will be returned.
func RunRemoteCommand(
	user string,
	host string,
	port uint32,
	command string,
	connectionTimeout time.Duration,
	absoluteDeadline time.Time,
	idleTimeout time.Duration,
	stdOutAndErr chan string,
	privateKeys ...[]byte) error {
	client, con, err := CreateSSHClient(
		user,
		host,
		port,
		connectionTimeout,
		absoluteDeadline,
		privateKeys...)
	if err != nil {
		return fmt.Errorf("Error creating SSH client: %s", err)
	}
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("Error creating SSH session: %s", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("Error hooking stdout: %s", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("Error hooking stderr: %s", err)
	}
	err = session.Start(command)
	if err != nil {
		return fmt.Errorf("Error running command: %s", err)
	}
	stdOutResChan := make(chan error)
	go scanOutput(
		&stdout,
		stdOutAndErr,
		stdOutResChan,
		absoluteDeadline,
		idleTimeout,
		con)
	stdErrResChan := make(chan error)
	go scanOutput(
		&stderr,
		stdOutAndErr,
		stdErrResChan,
		absoluteDeadline,
		idleTimeout,
		con)
	stdOutErr := <-stdOutResChan
	stdErrErr := <-stdErrResChan
	err = session.Wait()
	if err == nil {
		if stdOutErr != nil {
			err = stdOutErr
		} else if stdErrErr != nil {
			err = stdErrErr
		}
	}
	return err
}

// RunLocalCommand executes the specified command on the local host's bash shell.
func RunLocalCommand(command string) ([]byte, []byte, error) {
	var stdErr []byte
	stdOut, err := exec.Command("/bin/bash", "-c", command).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stdErr = exitErr.Stderr
		}
	}
	return stdOut, stdErr, err
}

// CopyFileToServer copies a single file from localPath to remotePath on the
// specified host over SSH using SCP.
func CopyFileToServer(
	user string,
	host string,
	port uint32,
	localPath string,
	remotePath string,
	connectionTimeout time.Duration,
	absoluteDeadline time.Time,
	privateKeys ...[]byte) error {
	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("Error opening %s: %s", localPath, err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("Error stating %s: %s", localPath, err)
	}
	err = CopyFileStreamToServer(
		user,
		host,
		port,
		file,
		stat.Size(),
		stat.Mode().Perm(),
		remotePath,
		connectionTimeout,
		absoluteDeadline,
		privateKeys...)
	if err != nil {
		return fmt.Errorf("Error copying %s: %s", localPath, err)
	}
	return nil
}

// CopyFileStreamToServer copies a single file with contents to remotePath on
// the specified host over SSH using SCP.
func CopyFileStreamToServer(
	user string,
	host string,
	port uint32,
	contents io.Reader,
	size int64,
	perm os.FileMode,
	remotePath string,
	connectionTimeout time.Duration,
	absoluteDeadline time.Time,
	privateKeys ...[]byte) error {
	client, _, err := CreateSSHClient(
		user,
		host,
		port,
		connectionTimeout,
		absoluteDeadline,
		privateKeys...)
	if err != nil {
		return fmt.Errorf("Error creating SSH client: %s", err)
	}
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("Error creating SSH session: %s", err)
	}
	defer session.Close()
	in, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("Error hooking stdin: %s", err)
	}
	fileName := filepath.Base(remotePath)
	go func() {
		defer in.Close()
		fmt.Fprintf(in, "C%#o %d %s\n", perm, size, fileName)
		io.Copy(in, contents)
		fmt.Fprint(in, "\x00")
	}()
	cmd := fmt.Sprintf("scp -t %s", remotePath)
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("Error copying file via SCP: %s", err)
	}
	return nil
}

// CopyFileFromServer copies file from remotePath on host to localPath over SCP,
// setting perm on the local file copy.
func CopyFileFromServer(
	user string,
	host string,
	port uint32,
	localPath string,
	remotePath string,
	perm os.FileMode,
	connectionTimeout time.Duration,
	absoluteDeadline time.Time,
	privateKeys ...[]byte) error {
	file, err := os.OpenFile(localPath, os.O_CREATE|os.O_RDWR, perm)
	if err != nil {
		return fmt.Errorf("Error open local file %s for writing: %s", localPath, err)
	}
	defer file.Close()
	client, _, err := CreateSSHClient(
		user,
		host,
		port,
		connectionTimeout,
		absoluteDeadline,
		privateKeys...)
	if err != nil {
		return fmt.Errorf("Error creating SSH client: %s", err)
	}
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("Error creating SSH session: %s", err)
	}
	defer session.Close()
	session.Stdout = file
	err = session.Run(fmt.Sprintf("/bin/cat %s", remotePath))
	if err != nil {
		return fmt.Errorf("Error cat'ing remote file %s: %s", remotePath, err)
	}
	return nil
}
