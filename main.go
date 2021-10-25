package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"

	"oras.land/oras-go/pkg/context"
	"oras.land/oras-go/pkg/oras"

	"oras.land/oras-go/pkg/content"
)

const (
	layerMediaType   = "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
	bundleVersion    = ":1"
	bundleRepository = "ghcr.io/aquasecurity/appshield"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	reg, err := content.NewRegistry(content.RegistryOptions{})
	check(err)

	// Pull file(s) from registry and save to disk
	store := content.NewMemory()
	_, err = oras.Copy(context.Background(), reg, bundleRepository+bundleVersion, store, bundleRepository+bundleVersion, oras.WithAllowedMediaType(layerMediaType))
	check(err)
	//sha256:b6f3b8f5dc3d34236da734a5db9474467857e0caa762930ef789763bb0038dd4
	des, b, ok := store.GetByName("bundle.tar.gz")
	if !ok {
		panic("not found")
	}
	fmt.Println(des)

	gzf, err := gzip.NewReader(bytes.NewReader(b))
	check(err)

	tarReader := tar.NewReader(gzf)
	i := 0
	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		name := header.Name

		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			fmt.Println("(", i, ")", "Name: ", name)
		default:
			fmt.Printf("%s : %c %s %s\n",
				"Yikes! Unable to figure out type",
				header.Typeflag,
				"in file",
				name,
			)
		}

		i++
	}
}
