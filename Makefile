dataset-all:
	python3 src/data/make_dataset.py

dataset-test:
	python3 src/data/make_dataset.py 2021-12-01 2021-12-02

## Calculates the attacks for a day

attacks:
	python3 src/data/
