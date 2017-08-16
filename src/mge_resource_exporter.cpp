//============================================================================
// Name        : mge_resource_exporter.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>

#include <fcntl.h>

#include <archive.h>
#include <archive_entry.h>

#include <botan/block_cipher.h>
#include <botan/hex.h>
#include <botan/pipe.h>
#include <botan/cipher_filter.h>
#include <botan/data_snk.h>

static void usage();
static size_t writeArchive_targz(void *outbuffer, size_t buffSize, const char **filename);
static size_t getFileLength(const char *filename);

int main(int argc, char *argv[])
{
	std::vector<uint8_t> key = Botan::hex_decode("1936D1EDCFA373207DC1C4D25DA02F2F9967B62A2EF0A0A6EF78F32D997819A8");
	std::vector<uint8_t> iv =  Botan::hex_decode("701F03E84617DF23D3A54FC3F0962012");

	bool doEncrypt = false;
	std::string outputFilename{"exported_archive"};

	// If no argument is passed, print usage example
	if(argc < 2)
	{
		usage();
		exit(EXIT_FAILURE);
	}

	// Parse command-line argument
	int optind = 1;
	for(; optind < argc && argv[optind][0] == '-'; optind++)
	{
	        switch(argv[optind][1])
	        {
	        case 'o':
	        	outputFilename = argv[++optind];
	        	break;
	        case 'e':
	        	doEncrypt = true;
	        	break;
	        case 'f':
				doEncrypt = true;
				break;
	        default:
	            usage();
	            exit(EXIT_FAILURE);
	        }
	}

	// Check existence of each file provided and compute total size
	size_t totalSize = 0, allocateSize = 0;
	for(int i = optind ; i < argc ; i++)
	{
		std::ifstream file(argv[i]);
		if(not file)
		{
			std::cout << "Cannot open file \"" << argv[i] << "\"" << std::endl;
			exit(EXIT_FAILURE);
		}
		else
			totalSize += getFileLength(argv[i]);
	}
	allocateSize = totalSize;

	// Allocate a memory area large enough to contain the archive
	std::unique_ptr<char[]> buf(new(std::nothrow) char[allocateSize]);
	if(not buf)
	{
		std::cout << "Memory allocation failed : need " << allocateSize << " to store archive in memory" << std::endl;
		exit(1);
	}

	// Construct targz archive in memory
	size_t arsize = writeArchive_targz(buf.get(), allocateSize, (const char**)&argv[optind]);

	if(doEncrypt)
	{
		// Encrypt and write archive onto disk
		std::istringstream in({buf.get(), arsize});
		std::ofstream out(outputFilename);
		Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC", key, iv, Botan::ENCRYPTION), new Botan::DataSink_Stream(out));
		pipe.start_msg();
		in >> pipe;
		pipe.end_msg();
	}
	else
	{
		// Write the archive onto disk
		std::ofstream of(outputFilename, std::ios::binary);
		of.write(buf.get(),arsize);
	}

	return 0;
}

static void usage()
{
	std::cout << "Please give at least one file" << std::endl;
	std::cout << "Usage : mge_resource_exporter [-o outputfile] [-e] file1 file2 ..." << std::endl;
}

static size_t writeArchive_targz(void *outbuffer, size_t buffSize, const char **filename)
{
	struct archive *a;
	struct archive_entry *entry;
	struct stat st;

	constexpr size_t blockSize = 8192;
	char tmpbuff[blockSize];

	size_t used = 0;

	a = archive_write_new();
	archive_write_add_filter_gzip(a);
	archive_write_set_format_pax_restricted(a);
	archive_write_open_memory(a, outbuffer, buffSize, &used);

	while(*filename)
	{
		stat(*filename, &st);
		entry = archive_entry_new();
		archive_entry_set_pathname(entry, *filename);
		archive_entry_set_size(entry, st.st_size);
		archive_entry_set_filetype(entry, AE_IFREG);
		archive_entry_set_perm(entry, 0644);
		archive_write_header(a, entry);

		std::ifstream file2archive(*filename, std::ios::binary);
		if(not file2archive)
		{
			std::cout << "Unable to open file \"" << *filename << "\"" << std::endl;
			filename++;
			continue;
		}

		while(not file2archive.eof())
		{
			file2archive.read(tmpbuff, blockSize);
			size_t readed = file2archive.gcount();
			archive_write_data(a, tmpbuff, readed);
		}

		archive_entry_free(entry);
		filename++;
	}

	archive_write_close(a);
	archive_write_free(a);

	return used;
}

static size_t getFileLength(const char *filename)
{
	struct stat st;
	int rc = stat(filename, &st);
	return rc == 0 ? st.st_blocks*512 : -1;
	// st.st_blocks contains the number of blocks of 512B allocated for this file
	// See http://man7.org/linux/man-pages/man2/stat.2.html
}
