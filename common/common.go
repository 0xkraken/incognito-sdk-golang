package common

import (
	"encoding/binary"
	"log"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

// appDataDir returns an operating system specific directory to be used for
// storing application data for an application.  See AppDataDir for more
// details.  This unexported version takes an operating system argument
// primarily to enable the testing package to properly test the function by
// forcing an operating system that is not the currently one.
func appDataDir(goos, appName string, roaming bool) string {
	if appName == "" || appName == "." {
		return "."
	}

	// The caller really shouldn't prepend the appName with a period, but
	// if they do, handle it gracefully by trimming it.
	appName = strings.TrimPrefix(appName, ".")
	appNameUpper := string(unicode.ToUpper(rune(appName[0]))) + appName[1:]
	appNameLower := string(unicode.ToLower(rune(appName[0]))) + appName[1:]

	// Get the OS specific home directory via the Go standard lib.
	var homeDir string
	usr, err := user.Current()
	if err == nil {
		homeDir = usr.HomeDir
	}

	// Fall back to standard HOME environment variable that works
	// for most POSIX OSes if the directory from the Go standard
	// lib failed.
	if err != nil || homeDir == "" {
		homeDir = os.Getenv("HOME")
	}

	switch goos {
	// Attempt to use the LOCALAPPDATA or APPDATA environment variable on
	// Windows.
	case "windows":
		// Windows XP and before didn't have a LOCALAPPDATA, so fallback
		// to regular APPDATA when LOCALAPPDATA is not set.
		appData := os.Getenv("LOCALAPPDATA")
		if roaming || appData == "" {
			appData = os.Getenv("APPDATA")
		}

		if appData != "" {
			return filepath.Join(appData, appNameUpper)
		}

	case "darwin":
		if homeDir != "" {
			return filepath.Join(homeDir, "Library",
				"Application Support", appNameUpper)
		}

	case "plan9":
		if homeDir != "" {
			return filepath.Join(homeDir, appNameLower)
		}

	default:
		if homeDir != "" {
			return filepath.Join(homeDir, "."+appNameLower)
		}
	}

	// Fall back to the current directory if all else fails.
	return "."
}

// AppDataDir returns an operating system specific directory to be used for
// storing application data for an application.
//
// The appName parameter is the name of the application the data directory is
// being requested for.  This function will prepend a period to the appName for
// POSIX style operating systems since that is standard practice.  An empty
// appName or one with a single dot is treated as requesting the current
// directory so only "." will be returned.  Further, the first character
// of appName will be made lowercase for POSIX style operating systems and
// uppercase for Mac and Windows since that is standard practice.
//
// The roaming parameter only applies to Windows where it specifies the roaming
// application data profile (%APPDATA%) should be used instead of the local one
// (%LOCALAPPDATA%) that is used by default.
//
// Example results:
//  dir := AppDataDir("myapp", false)
//   POSIX (Linux/BSD): ~/.myapp
//   Mac OS: $HOME/Library/Application Support/Myapp
//   Windows: %LOCALAPPDATA%\Myapp
//   Plan 9: $home/myapp
func AppDataDir(appName string, roaming bool) string {
	return appDataDir(runtime.GOOS, appName, roaming)
}

// InterfaceSlice receives a slice which is a interface
// and converts it into slice of interface
func InterfaceSlice(slice interface{}) []interface{} {
	s := reflect.ValueOf(slice)
	if s.Kind() != reflect.Slice {
		log.Println("InterfaceSlice() given a non-slice type")
		return nil
	}

	ret := make([]interface{}, s.Len())

	for i := 0; i < s.Len(); i++ {
		ret[i] = s.Index(i).Interface()
	}

	return ret
}

// SliceExists receives a slice and a item in interface type
// checks whether the slice contain the item or not
func SliceExists(slice interface{}, item interface{}) (bool, error) {
	s := reflect.ValueOf(slice)

	if s.Kind() != reflect.Slice {
		return false, errors.New("SliceExists() given a non-slice type")
	}

	for i := 0; i < s.Len(); i++ {
		interfacea := s.Index(i).Interface()
		if interfacea == item {
			return true, nil
		}
	}

	return false, nil
}

// GetShardIDFromLastByte receives a last byte of public key and
// returns a corresponding shardID
func GetShardIDFromLastByte(b byte) byte {
	return byte(int(b) % MaxShardNumber)
}


// BytesToInt32 converts little endian 4-byte array to int32 number
func BytesToInt32(b []byte) (int32, error) {
	if len(b) != Int32Size {
		return 0, errors.New("invalid length of input BytesToInt32")
	}

	return int32(binary.LittleEndian.Uint32(b)), nil
}

// Int32ToBytes converts int32 number to little endian 4-byte array
func Int32ToBytes(value int32) []byte {
	b := make([]byte, Int32Size)
	binary.LittleEndian.PutUint32(b, uint32(value))
	return b
}

// IntToBytes converts an integer number to 2-byte array in big endian
func IntToBytes(n int) []byte {
	if n == 0 {
		return []byte{0, 0}
	}

	a := big.NewInt(int64(n))

	if len(a.Bytes()) > 2 {
		return []byte{}
	}

	if len(a.Bytes()) == 1 {
		return []byte{0, a.Bytes()[0]}
	}

	return a.Bytes()
}

// BytesToInt reverts an integer number from 2-byte array
func BytesToInt(bytesArr []byte) int {
	if len(bytesArr) != 2 {
		return 0
	}

	numInt := new(big.Int).SetBytes(bytesArr)
	return int(numInt.Int64())
}

// BytesToUint32 converts big endian 4-byte array to uint32 number
func BytesToUint32(b []byte) (uint32, error) {
	if len(b) != Uint32Size {
		return 0, errors.New("invalid length of input BytesToUint32")
	}
	return binary.BigEndian.Uint32(b), nil
}

// Uint32ToBytes converts uint32 number to big endian 4-byte array
func Uint32ToBytes(value uint32) []byte {
	b := make([]byte, Uint32Size)
	binary.BigEndian.PutUint32(b, value)
	return b
}

// BytesToUint64 converts little endian 8-byte array to uint64 number
func BytesToUint64(b []byte) (uint64, error) {
	if len(b) != Uint64Size {
		return 0, errors.New("invalid length of input BytesToUint64")
	}
	return binary.LittleEndian.Uint64(b), nil
}

// Uint64ToBytes converts uint64 number to little endian 8-byte array
func Uint64ToBytes(value uint64) []byte {
	b := make([]byte, Uint64Size)
	binary.LittleEndian.PutUint64(b, value)
	return b
}

// Int64ToBytes converts int64 number to little endian 8-byte array
func Int64ToBytes(value int64) []byte {
	return Uint64ToBytes(uint64(value))
}

// BoolToByte receives a value in bool
// and returns a value in byte
func BoolToByte(value bool) byte {
	var bitSetVar byte
	if value {
		bitSetVar = 1
	}
	return bitSetVar
}

// AddPaddingBigInt adds padding to big int to it is fixed size
// and returns bytes array
func AddPaddingBigInt(numInt *big.Int, fixedSize int) []byte {
	numBytes := numInt.Bytes()
	lenNumBytes := len(numBytes)
	zeroBytes := make([]byte, fixedSize-lenNumBytes)
	numBytes = append(zeroBytes, numBytes...)
	return numBytes
}