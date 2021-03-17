package lb

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

func bindata_read(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	return buf.Bytes(), nil
}

var _bpf_xdp_forwarder_c = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x19\x69\x6f\xdb\x38\xf6\xbb\x7e\xc5\x9b\x14\x08\x64\x47\xb9\xdc\x20\x53\xac\xc7\x01\xd2\xc4\xdd\x06\x93\x26\x46\xe2\x00\x5d\x0c\x16\x04\x2d\x52\x36\x11\x8a\x14\x48\x2a\x6d\x66\x90\xfe\xf6\x05\x0f\x1d\x96\xe5\xb6\x3b\xd8\x62\x17\x8b\xf1\x97\x48\xef\xe2\x3b\xf8\x2e\xe5\xf0\xf0\x15\xa1\x19\x13\x14\x7e\x7d\xfb\x70\x75\x7d\x89\x3e\xdc\x5e\xde\x9c\x7f\x98\xc2\x4e\x26\xd5\x27\xac\x08\x55\x3b\x51\x43\x84\x75\x8e\x9e\x24\xc7\x86\x71\x8a\x96\xd2\xc8\xf8\xf3\xc1\xc1\xc1\x20\x7a\xc5\x44\xca\x4b\x42\xe1\x17\xce\x44\xf9\xf9\x70\x51\x64\x07\xab\xb3\x0d\x30\xcb\x10\x35\x2b\xaa\xb6\xe0\x0a\x9c\x3e\x52\xd3\x8b\x14\xfd\xd0\x2d\xd4\x45\x3f\xf4\xe9\xb4\x0f\x5e\x12\x47\xde\xb2\xf2\x72\xfa\xf6\xe1\xef\x70\x1c\x55\xef\xb3\xbb\xdb\xf9\x2d\x7a\xb8\x9c\xc1\xf1\xcf\x35\xf0\xc3\xf9\x47\x74\x37\xbd\xbc\xba\x9b\x5e\xcc\xd1\xf4\x66\x7e\x77\x35\xbd\x87\xd1\xe9\xe8\xf8\xe4\xa8\xa6\x99\xdf\xce\xcf\xaf\x2d\x23\x7a\x7f\x3d\xbd\x81\xe9\xfc\xbd\x7f\xd8\x03\xcd\x7e\xa7\x32\x8b\xb5\x51\x65\x6a\x80\x15\x2b\xa2\x06\x1b\xe0\x92\x38\x78\x14\x85\xf7\x8c\xcb\x4f\xe8\x91\x3e\x23\x03\x7f\x44\x00\x08\x95\xaf\x47\x40\xb4\x41\x98\x10\x35\x86\xc3\x43\x38\x81\xc5\xb3\xa1\xba\x46\x6a\x95\x6e\x41\x1e\x9f\x3a\xce\x42\x2a\xe3\x90\xa3\x0e\xd2\x72\xf6\x23\x5f\x8f\xa0\xc0\x64\x0c\xee\x77\x78\x68\x5f\x08\x13\xcb\xe8\x65\xbc\xae\xe8\x13\xe6\xfd\x8a\x6e\x6a\xb7\xa9\xd2\xa6\x1e\xeb\x87\xb7\xce\x75\xf0\xd3\x13\xe0\x58\x1b\x54\x6a\x4a\xc6\x6d\x55\xe8\x13\x15\xa6\xd1\xe3\x0d\xe8\x1c\xa7\xbf\x9d\xfe\x73\x5c\xbd\x93\xb5\xf7\x5e\xad\x36\x75\xe8\xd8\xd2\xd1\x3c\x5d\x61\x05\x39\xd5\x1a\x2f\xe9\x6f\xc7\xa3\x37\x41\xb8\x7e\x3d\x82\x54\x12\x3a\x8e\x5e\x00\x21\x6c\x8c\x62\x8b\xd2\x50\x84\xe2\xd8\xdd\x7c\x32\x18\x8c\xed\x35\xb4\x71\xf7\x7a\x6b\x2b\x4a\x08\xca\xa3\xb7\xb3\x77\x68\x36\xbd\x7b\x87\x6e\x1f\xe6\xb3\x87\x79\x5c\x92\x02\x79\x92\xc0\xc3\x99\x36\x54\x30\xb1\x04\xab\x85\x86\x1c\x17\x8e\xe9\xfd\xf9\xfd\xfb\xd8\x81\x12\xaf\xa9\xfb\xf3\xc6\x72\xd5\x68\x1b\x2e\x9d\xc0\xc6\x2d\x5b\x07\xb9\x78\x26\xbd\xf7\xde\x4a\xeb\x58\x84\x10\xe6\x9f\xf0\xb3\x46\x4c\x70\x26\x28\x42\x83\x01\x68\x83\x0d\x4b\xc1\x43\xbc\x36\x51\xaa\xcb\x1c\x65\x92\x13\xb4\xa2\xbc\xa0\x2a\xf6\xc1\xb4\xe0\x81\x0b\x1a\x13\x06\xd8\x38\x7a\x55\x28\xbc\xcc\x31\x94\x42\x49\xce\x23\x80\x4c\x2a\x88\x19\x4c\xe0\x68\x0c\x0c\x7e\x81\x93\x31\xb0\xbd\x3d\xcf\x03\xc0\x32\x88\xad\x0c\x38\x3b\x83\xe3\xd3\x41\xe4\x6f\xab\x83\x4c\x02\x66\x17\x8e\x3e\x67\x59\x96\xd9\xbc\x6b\xd3\xda\x60\xbd\x44\x00\x8a\x9a\x52\x09\xf8\x62\x51\xe3\xe8\xe5\x4f\x58\xf8\x24\x19\x89\x58\xf1\x74\x82\x9c\x95\x1e\x1a\x5b\x28\x0c\x59\xb1\x4a\xc2\xc5\x1d\x36\xc6\xfa\xbb\x34\x14\xf4\xb3\x41\xac\x58\xb9\xb7\x09\xc4\x01\x3c\x60\xc5\xaa\xf1\x44\xca\xb1\x58\x02\x97\xb2\x08\x4e\x89\xb3\x92\xf3\x41\xed\x1a\xeb\xb7\xc6\x3d\xbd\x05\xc7\x1a\xbc\xe6\x36\xa7\x0a\xec\x4d\xd6\x55\xd8\xdb\xab\x7c\x32\x0c\x1e\xdc\x88\x9a\xb7\xe1\x3f\xe1\xa6\xe0\x1f\x82\x0d\x46\xda\x60\x65\x12\x77\x05\xfc\x3b\xfb\x9d\xf6\x78\xad\xd2\x6a\x51\x64\xde\xd3\x84\x65\x59\x7c\x94\xc0\x51\x02\x6d\x39\x2d\x19\x95\xbe\x3f\xd2\xa4\xb2\x20\xd8\x50\x6f\x54\x4b\x67\x6b\xc0\x82\xbe\x1e\x81\x3d\xcb\x16\x91\x1a\x20\xe8\x27\x07\xf0\x56\x1d\x1e\xc2\x97\xf7\x17\x2d\x0d\xbf\x0c\xfd\x55\x6c\x20\xc3\xb5\x8b\x3c\xf6\x4c\x7b\xf0\x25\xaf\x0b\x95\xc9\x0b\x0b\x36\x79\x61\x05\x54\x27\x36\x32\xf6\x26\x15\x89\xe3\xcc\xdb\x88\x4a\x9d\x80\x35\x2b\x2a\xc0\x3a\x08\xb0\x20\x90\xca\xbc\xe0\x34\xa7\xc2\x80\xa2\xba\xe4\x06\x7e\xfa\x4e\x67\x6e\x7a\x0a\x32\xa6\xa8\x2f\x67\xd5\x05\xbd\x98\x7f\x9c\xff\x63\x36\x85\xa1\x7e\x5c\x24\x90\x4a\xa1\x8d\x2f\xab\xc3\x50\x57\x93\x90\xd2\xdb\x7e\x4d\xb9\xb5\xde\x7c\xc5\x32\x42\x33\xdf\xd8\x23\x80\xe6\x8a\xd9\xec\xf2\x6f\x83\x98\x4b\xb1\x1c\xe8\xc7\xc5\xfe\x99\xc5\x8c\xd7\xe8\x10\x15\x64\x3b\xad\xc5\x5a\xfa\xaa\xe7\x98\xd5\x8a\x28\x18\x52\xb3\x82\x09\x54\xc2\xda\xa9\x67\xf3\xdf\x8a\x73\x2a\x74\xdb\xbe\x67\x1f\x0c\x5a\x4c\x7e\x12\x80\xa1\xed\x0c\xdf\x60\xdb\x32\x5c\xb4\xa5\x55\x3d\xd1\xfd\x85\x09\xfc\x61\xfb\xa5\x8b\x71\xa8\x79\x14\x2b\xfe\x6c\x6b\xa8\x90\x06\xa8\x90\xe5\x72\xe5\xcc\x88\x7c\x61\x0d\xc7\x77\xa6\x9b\x33\xa8\x5c\x51\x55\x13\x2f\xcd\xd7\x0e\x2f\x5f\x0a\xfe\x0c\x57\x33\xf0\x93\x9e\x06\xac\x28\x60\xce\xe5\x27\x4a\x82\x6c\x6a\x56\xfb\x67\x2b\x54\x28\x69\x24\xfc\x34\x81\x95\x91\x42\xc7\x76\x72\x9a\xa1\xab\xd9\xe0\x1b\xa2\x1f\x2e\x67\x41\x0e\x2b\xf6\xcf\x9c\x90\x54\x72\x2b\xa7\x9e\xe1\xb6\x48\x08\x67\x5b\xd2\x9b\x87\xeb\xeb\x8a\x0a\xa1\x45\xc9\xb8\x61\x02\xe5\x34\x4f\x8b\xe7\x78\xd7\x39\xed\xc0\x4e\x11\x09\x04\x65\xb5\x2c\x55\x4a\x13\xf0\xbd\x63\x3b\x13\x69\x33\x11\xaa\x4d\xc5\x52\x6b\xc0\x8a\xae\x02\xe1\xb8\x30\x93\xc0\x04\xac\x61\xba\x4a\xcb\x0a\x5f\xcd\x23\x01\x4f\x2a\x7c\x2d\xd8\x5e\x9c\xad\x92\xed\x78\x00\x13\x7b\xc9\xf6\xcf\xbc\x2d\x5d\xd9\x6d\x0a\xab\x78\x2d\xdb\x93\xd8\x34\x03\x1f\x2b\x1e\xbb\x9c\x1b\x87\x73\x43\xb6\x7e\xaf\x5b\xab\xe4\x86\xfa\xe1\x78\xf4\xb3\x77\x11\x50\xae\xe9\xf7\xb2\xef\xec\xb4\x38\x23\x80\x66\x5c\x3a\x28\xa8\xca\x90\x2e\x17\x39\x33\xb1\x2b\x2e\x9e\x37\xa9\xb2\xc6\xbd\xd9\x74\x79\x45\x05\x61\xd9\x96\x8a\x15\x6a\x7b\x3d\x73\xf6\xd6\xad\x6f\x94\x28\xff\xdb\x9c\xed\x87\xd5\xf3\xbf\x2f\xc0\xcf\xdc\x4e\x40\x02\xed\x02\x58\x4f\xc9\x86\xe5\x54\x1b\xec\xfa\x81\xed\x97\x8f\x16\x80\x96\xd4\x20\xa1\xe3\x3a\x6c\x3e\xa0\x13\xf8\x78\x39\x43\xf3\x8f\x55\xd4\xac\xd8\xfd\xb3\xda\x66\x98\x34\xd2\xc6\x35\x81\x3e\xf0\xbe\x89\x6b\x2b\x1c\x38\xa4\x46\xbb\xd2\x5b\xe7\xef\x28\x4a\x98\xa2\xa9\xa1\x24\x14\x85\x83\x9d\x04\xc2\x15\x6a\x87\xfd\xeb\xdc\x90\x61\xc6\x29\x69\x58\x6d\xd8\x5f\xec\x5c\x9c\x97\x06\x1b\xaa\x6d\xf7\x82\x25\x7b\xa2\x22\x1c\x03\x8b\x32\xcb\xa8\xfa\x1b\x68\x6a\xe0\x7a\xb4\x7f\x7d\x02\x19\xa3\x9c\xe8\x04\x14\x4d\x31\x4f\x4b\x8e\x0d\x85\x74\x45\xd3\x47\x5d\xe6\x3a\xaa\xab\xa3\x0e\x5e\x01\x29\x40\x97\x69\x4a\xb5\x4e\x1c\x68\x76\x7e\x7f\x6f\xbd\xc7\xc4\x13\xe6\x8c\x78\xe0\xe5\xdd\xed\xcc\x57\x52\x50\xb2\x34\x14\x98\x86\x4c\x96\x82\x74\x6e\x95\x9d\x71\xbc\xae\x61\x0d\xee\xef\x84\x5b\x82\x5d\x4d\x8f\x36\xe4\x8a\x9a\xf1\x5f\x3d\xce\xde\xed\x8c\x2d\x10\x97\xf2\xb1\x2c\xc0\x3e\x16\x58\xe1\x5c\xff\xd7\xfa\x60\x7d\x47\x7e\x60\x43\xec\x3d\x63\xa9\xf0\x02\xa4\x62\x4b\x26\x30\x07\x5b\xbe\x99\xc0\x86\x49\x01\xb6\x4d\xac\xed\xbd\x2e\x62\x6b\x1d\xa6\xd9\x77\x6b\x1c\x69\x70\x0b\xda\x5a\x7d\xbb\x0d\x22\xa0\xb7\x75\x98\xa8\x53\xc7\x35\x35\xf1\x6e\x13\x27\x37\xbd\x87\x28\x37\x50\x1f\xe3\xe6\xfd\x20\xc3\x39\xe3\xcf\x30\x81\xf3\x77\xe8\xea\x66\x3a\xef\xa0\x8d\xd4\x41\x6b\x23\x75\x07\xc7\x4f\x50\x3d\x21\x78\x9a\xea\xb5\x43\xa8\x83\xfa\x47\x1d\x38\xd9\x02\x37\xd2\x20\x4e\x45\xa8\xb0\xc2\xc8\x95\x8e\xbd\x0a\x0e\xde\x35\xc1\xad\x3e\x5a\xa5\x30\x09\x15\xb6\xfd\x05\xa2\x4b\x47\xb4\xa9\xe9\xda\x5f\x21\xda\x74\x19\x13\x84\x7e\x86\x09\xb8\xe4\x65\x62\xa9\xa8\xd6\x28\x80\x9d\xe3\x15\x35\x41\xbb\x26\x47\x42\x37\x6c\x47\x60\xd3\xfd\x5b\x5b\xd2\xdb\xd9\x3b\xf4\xee\xea\x2d\xba\xbe\xbd\xfd\xf5\x61\x86\xfc\xf7\x01\x5f\xc3\xed\x2d\xb6\x07\xfe\x34\x69\xa8\x2c\xcd\xdd\x74\x8e\xee\x1f\x2e\x2e\xa6\xf7\xf7\x75\x87\xe9\x16\xf8\x8c\x2d\xa0\x4a\xe1\xaa\xc4\x2b\x6a\x42\x37\x69\x5d\x7a\x5b\x67\xeb\x4b\xdf\x33\x1f\xb4\x87\xae\x76\x08\xdd\x48\x66\xb3\xe9\xfc\x7a\x7a\x33\x18\x7f\x8d\xb9\x1a\xf3\xda\x37\xa3\xcb\x6e\xcd\xad\xd2\xa7\x37\x9e\x75\x02\xf5\x46\xb1\x95\x20\x6b\xdc\xd5\x97\xa5\x3a\xbf\xd6\xb8\x3d\xb6\x6e\xf1\x61\x07\x3b\xaa\x8e\x73\x3d\xac\x01\x54\x7b\x36\x2b\x92\xde\x2a\x9a\xc0\x6e\xbd\x1c\xb7\xd9\xfd\xf2\x19\xd5\x5f\x51\x9c\x2e\x0e\xe9\x34\x6b\x2d\xbb\xbb\x7e\xcd\xf5\x05\x25\x69\x1c\x32\xf8\x0a\xa1\xb5\x21\x69\xdb\xbf\x8d\xd8\x97\xa2\xa4\x71\xe4\xd7\x08\x5b\x52\xad\xd7\x06\xb5\x0f\xd7\x8d\x5a\xbb\x49\xf3\x8f\x3d\x6b\xaa\x6d\xcf\xe1\x8b\x78\x5f\x63\xfe\xab\xff\x76\xa5\x75\x27\x14\xf0\x0b\xc0\xff\x65\x83\xfd\x73\xab\xe7\xa6\x28\xff\x99\x63\x73\x21\xa8\x1e\xed\x88\x12\xea\x6f\xef\xc6\x57\x15\xe7\xde\x75\x31\x69\x73\x76\xdb\xf5\x1a\xe7\x66\xb3\xae\xd1\x05\x26\xf5\x9e\x77\xe4\x9a\x41\x3d\x32\x31\x91\xca\xdc\x7d\x7f\xf6\x9e\x0e\xce\x70\x9f\x9e\x0f\x42\x87\xd9\x8d\x9b\x54\x1c\xb4\xb7\x8a\x50\xce\x1a\xc2\xca\xe4\x50\xe8\xad\x24\x4f\xb7\xbe\x47\xf6\x74\x0c\xdb\x48\xeb\xb5\xc0\x5e\x2b\x37\x6d\xef\x24\xb0\xff\x3a\x08\xeb\x0d\x40\x08\x41\xd5\x1a\x3b\xa3\xb8\x95\xdc\xda\x62\x36\xb7\x3f\xdf\x3a\xd7\x36\x9e\x9e\x46\xe5\x4a\x83\x03\xb8\x14\xd0\x85\x14\x9a\xb6\x1c\x16\xb6\x9d\x6d\x7e\x0b\x85\xf1\x47\x79\x4e\x48\xd0\x02\xdb\x3c\x34\xea\xb9\x71\xdb\xf1\xd1\xff\x96\xdf\xdc\x3f\x38\xec\x1a\x65\x83\x9b\x63\x81\x97\x2e\x95\xd7\x3e\x10\x6c\xd8\x66\xc7\xa6\x1e\x3e\x6b\xdf\x68\x73\x98\x68\xb2\xf2\xc5\xfd\x73\x25\xc7\x4c\x78\xb7\x14\x92\x09\xd3\xde\x05\xe7\x17\xe8\xfc\x62\x8e\x86\x51\xab\x43\x50\xb5\xa5\x47\x54\x67\xd4\x9d\xe4\x71\x31\x18\xc3\x4b\xf4\xaf\x00\x00\x00\xff\xff\x95\x5a\x73\x4b\x86\x1d\x00\x00")

func bpf_xdp_forwarder_c() ([]byte, error) {
	return bindata_read(
		_bpf_xdp_forwarder_c,
		"bpf/xdp_forwarder.c",
	)
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		return f()
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() ([]byte, error){
	"bpf/xdp_forwarder.c": bpf_xdp_forwarder_c,
}
// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for name := range node.Children {
		rv = append(rv, name)
	}
	return rv, nil
}

type _bintree_t struct {
	Func func() ([]byte, error)
	Children map[string]*_bintree_t
}
var _bintree = &_bintree_t{nil, map[string]*_bintree_t{
	"bpf": &_bintree_t{nil, map[string]*_bintree_t{
		"xdp_forwarder.c": &_bintree_t{bpf_xdp_forwarder_c, map[string]*_bintree_t{
		}},
	}},
}}