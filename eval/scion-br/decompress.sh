#!/bin/sh

mkdir -p loop-cable
tar -xzvf loop-cable.tar.gz -C loop-cable

mkdir -p osr
tar -xzvf osr.tar.gz -C osr

mkdir -p p4-cmac-1pipe
tar -xzvf p4-cmac-1pipe.tar.gz -C p4-cmac-1pipe

mkdir -p p4-cmac-2pipes
tar -xzvf p4-cmac-2pipes.tar.gz -C p4-cmac-2pipes

mkdir -p p4-no-cmac
tar -xzvf p4-no-cmac.tar.gz -C p4-no-cmac

mkdir -p pipe-recirc
tar -xzvf pipe-recirc.tar.gz -C pipe-recirc

mkdir -p sidn-p4
tar -xzvf sidn-p4.tar.gz -C sidn-p4
