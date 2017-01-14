
#include <boost/program_options/cmdline.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/filesystem.hpp>
#include <boost/date_time/posix_time/posix_time.hpp> //include all types plus i/o

#include <boost/thread.hpp>
#include <boost/container/vector.hpp>

#include "keyCandidateDistributor.h"

#include <boost/asio.hpp>
#include <csignal>

#include "OptionPrinter.h"

#include "gpu_code.h"
#include "cpu_code.h"

#include <stdio.h>
#include <string.h>

#include <stdlib.h>     /* srand, rand */
#include <time.h>       /* time */

#include "salsa20.h"
#include "petya.h"

#include "xmlStore.h"

#define VERBOSE 0


#include <iostream>

namespace po = boost::program_options;
using namespace std;

bool shutdownRequested = false;

uint64_t nrOfKeysSearched = 0;
char* veribuf;
char* nonce;

bool keyFound = false;

boost::asio::io_service io_service;
boost::asio::signal_set signals(io_service, SIGINT, SIGTERM);
void handler(
    const boost::system::error_code& error,
    int signal_number)
{

  // cout << "Signal handler" <<endl;

  if (!error)
  {
    // A signal occurred.
	  switch (signal_number) {
	  case SIGTERM:   shutdownRequested = true;
	  	  	  	  	  //cout << "SIGTERM received" << endl;
	  	  	  	  	  break;
	  case SIGINT:   shutdownRequested = true;
	  	  	  	  	  // ctr+c pressed
	  	  	  	  	  //cout << "SIGINT received" << endl;
	  	  	  	  	  break;
	  default:       signals.async_wait(handler);
		  	  	     break;
	  }

//	  cout << "Signal occured" <<endl;
  }

}

void setupSignalHandler() {

	// io_service.poll();

	// Construct a signal set registered for process termination.
	// Start an asynchronous wait for one of the signals to occur.
	//boost::bind(&handler, this);
	signals.async_wait(handler);
	io_service.run();
    // io_service.poll();

}

void printTimeEstimation(uint64_t keysCalculated, uint64_t nrOfSecondsInTotalMeasured) {
	uint64_t totalSecondsToCalculateAllKeys = (pow(2*26+10,8) / keysCalculated)*nrOfSecondsInTotalMeasured;
	uint64_t years = totalSecondsToCalculateAllKeys /60/60/24/365;
	uint64_t days = (totalSecondsToCalculateAllKeys /60/60/24)-years*365;
	uint64_t hours = (totalSecondsToCalculateAllKeys /60/60)-(years*365*24+days*24);
	uint64_t minutes = (totalSecondsToCalculateAllKeys /60)-(years*365*24*60+days*24*60+hours*60);

	std::cout << years << " years" << endl;
	std::cout << days << " days" << endl;
	std::cout << hours << " hours" << endl;
	std::cout << minutes << " minutes" << endl;

}

void checkShutdownRequested(){
	if (shutdownRequested){
		io_service.stop();
		cout << "Program interrupted" << endl;
		exit(0);
	}
}



int main(int argc, char *argv[])
{
	uint64_t totalKeyRange = 2 * 26 + 10;
	
	for (int i = 0; i < 7; i++) {
		totalKeyRange *= 2 * 26 + 10;
	}
	// (unsigned long)pow((2 * 26 + 10), 8);

	std::string appName = boost::filesystem::basename(argv[0]);

	bool enableCPU;
	bool enableGPU;

	po::options_description commandLineOptions;

	po::options_description generic("Options");
	generic.add_options()
	    ("help", "display help message")
		("version", "output the version number")
	    ("file", po::value<string>(), "filename which contains disk dump of crypted harddrive (does only need to be the first 57 sectors)")
		("resume", "resume previous calculation")
	    ("key", po::value<string>(), "try a specific key")
	;

	po::options_description optionalGPU("Optional GPU Arguments");
	optionalGPU.add_options()
		("queryDeviceInfo", "Displays information about NVIDIA devices")
		("gpu_threads", po::value<uint64_t>()->default_value(1024), "number of threads to use on GPU")
	    ("gpu_blocks", po::value<uint64_t>()->default_value(1), "number of blocks to use on GPU")
	    ("gpu_keysCtxSwitch", po::value<uint64_t>()->default_value(10000), "number keys which are calculated on a the gpu before the context switches back to host")
	;

	po::options_description optionalCPU("Optional GPU Arguments");
	optionalCPU.add_options()
	    ("cpu_threads", po::value<uint64_t>()->default_value(10), "nr of threads to use on CPU for CPU calculation")
	;

	po::options_description optionalGeneric("Optional Generic Arguments");
	optionalGeneric.add_options()
		("start_key", po::value<uint64_t>()->default_value(0), "start key number (defaults to 0)")
	    ("nrOfKeysToCalculate", po::value<uint64_t>()->default_value(totalKeyRange), "nr of keys which should be calculated before program ends [defaults to all key combinations (2*26+10)^8]")
	;

	po::positional_options_description positionalOptions;
	positionalOptions.add("file", 1);

	commandLineOptions.add(generic).add(optionalCPU).add(optionalGPU).add(optionalGeneric);


	boost::thread signalHUPThread(setupSignalHandler);

	po::variables_map vm;

	try {
		// po::store(po::parse_command_line(argc, argv, commandLineOptions), vm);
		po::store(po::command_line_parser(argc, argv).options(commandLineOptions)
		            .positional(positionalOptions).run(), vm);

		po::notify(vm);


		petya_decryptor_settings settings;

		uint64_t resumeKeyNumber = -1;
		uint64_t calculatedKeyBlockSize = -1;
		if (vm.count("resume")) {
			settings.load("settings.xml");

			resumeKeyNumber = settings.resume_keyNr;
			calculatedKeyBlockSize = settings.calculatedKeyBlockSize;
		} else {

			cout << "File count is "<< vm.count("file") << endl;

			if (vm.count("file")) {
				settings.m_file= vm["file"].as<string>();
			}

			if (vm.count("start_key")) {
				settings.start_keyNr = vm["start_key"].as<uint64_t>();
			}

			if (vm.count("nrOfKeysToCalculate")) {
				settings.nrOfKeysToCalculate = vm["nrOfKeysToCalculate"].as<uint64_t>();
			}

			if (vm.count("gpu_blocks")) {
				settings.gpu_blocks = vm["gpu_blocks"].as<uint64_t>();
			}

			if (vm.count("gpu_threads")) {
				settings.gpu_threads = vm["gpu_threads"].as<uint64_t>();
			}

			if (vm.count("cpu_threads")) {
				settings.cpu_threads = 	vm["cpu_threads"].as<uint64_t>();
			}

			if (vm.count("gpu_keysCtxSwitch")) {
				settings.gpu_keysCtxSwitch = vm["gpu_keysCtxSwitch"].as<uint64_t>();
			}
		}



		if (vm.count("help")) {

			rad::OptionPrinter::printStandardAppDesc(appName,
															 std::cout,
															 commandLineOptions,
															 &positionalOptions);

			io_service.stop();


			return 1;
		}

		if (vm.count("version")) {
			cout << appName << " Version 1.0 customized by alexander-schranz" << endl;
			io_service.stop();

			return 0;
		}

		if (vm.count("queryDeviceInfo")) {
			uint64_t nrBlocks;
			uint64_t nrThreads;
			queryDeviceInfo(&nrBlocks, &nrThreads);
			io_service.stop();

			return 0;

		}

		char p_key[KEY_SIZE+1];
		char *key = p_key;

		if (settings.m_file.empty()) {
			rad::OptionPrinter::printStandardAppDesc(appName,
															 std::cout,
															 commandLineOptions,
															 NULL ); // &positionalOptions

			io_service.stop();

			return -1;
		}



		string filenameStr = settings.m_file;


		const char* filename = filenameStr.c_str(); // argv[1];
		FILE *fp = fopen(filename, "rb");
		if (fp == NULL) {
			printf("Cannot open file %s\n", filename);
			io_service.stop();

			return -1;
		}

		if (is_infected(fp)) {
			printf("[+] Petya FOUND on the disk!\n");
		} else {
			printf("[-] Petya not found on the disk!\n");
			io_service.stop();

			return -1;
		}
		veribuf = fetch_veribuf(fp);
		nonce = fetch_nonce(fp);

		if (!nonce || !veribuf) {
			printf("Cannot fetch nonce or veribuf!\n");
			io_service.stop();

			return -1;
		}
		printf("---\n");
		printf("verification data:\n");
		hexdump(veribuf, VERIBUF_SIZE);

		printf("nonce:\n");
		hexdump(nonce, NONCE_SIZE);
		printf("---\n");
                
                size_t veri_size = 8;

		if (true) {
			//initializeAndCalculate((uint8_t *)nonce,  veribuf);

			unsigned int gpuThreads = settings.gpu_threads;
			unsigned int gpuBlocks = settings.gpu_blocks;
			uint64_t ctxSwitchKeys = settings.gpu_keysCtxSwitch;

			unsigned int nrKeys = gpuThreads*gpuBlocks;
			char *keys = (char *) malloc(nrKeys*sizeof(char)*KEY_SIZE);

			uint64_t startKey = settings.resume_keyNr!=-1 ? settings.resume_keyNr : settings.start_keyNr;
			uint64_t nrOfKeysToCalculate = settings.nrOfKeysToCalculate;

			uint64_t currentKeyIndex = startKey;
			char *currentKey = keys;

			uint64_t blockSize = settings.calculatedKeyBlockSize!=-1 ? settings.calculatedKeyBlockSize : (nrOfKeysToCalculate / (uint64_t) nrKeys)+1;

			for (int i=0; i<nrKeys; i++) {
				calculate16ByteKeyFromIndex(currentKeyIndex, currentKey);
				currentKey+=KEY_SIZE;
				currentKeyIndex += blockSize;
			}


			// Save XML before the calculation begins...
			settings.resume_keyNr = calculateIndexFrom16ByteKey(keys);
			settings.calculatedKeyBlockSize = blockSize;
			settings.save("settings.xml");

			cout << "Starting calculation with "<< endl;
			cout << " Blocks....................................... " <<gpuBlocks  << endl;
			cout << " Threads...................................... " << gpuThreads << endl;
			cout << " Keys calculated before GPU context returns... " << ctxSwitchKeys  << endl;
			cout << " Number of keys to calculate.................. " << nrOfKeysToCalculate << endl;
			cout << " Calculated Key Block size.................... " << blockSize << endl;


			tryKeysGPUMultiShot(gpuBlocks,
								gpuThreads,
								(uint8_t *)nonce,
								veribuf,
								keys,
								nrKeys,
								ctxSwitchKeys,
								nrOfKeysToCalculate,
								false, 
								&shutdownRequested);


			if (shutdownRequested) {
				// Save XML File...
				settings.resume_keyNr = calculateIndexFrom16ByteKey(keys);
				settings.calculatedKeyBlockSize = blockSize;

				settings.save("settings.xml");
			}
			free(keys);
			io_service.stop();

			checkShutdownRequested();
			return 0;
		}


		 //<< vm["file"].as<string>() << ".\n";


	}
	catch (std::exception& ex) {
		rad::OptionPrinter::printStandardAppDesc(appName,
		                                                 std::cout,
		                                                 commandLineOptions,
		                                                 NULL ); // &positionalOptions


	}

	io_service.stop();

	return -1;




}

