#!/usr/bin/env bash

pushd templates
python name_length.py > ../policies/name_length.rego
popd