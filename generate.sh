#!/usr/bin/env bash

pushd templates
python name_length.py > ../policy/name_length.rego
popd