# hybrid-bb84-mlkem-demo

This project is a simulation of a hybrid key exchange protocol that combines the BB84 quantum key distribution protocol with the ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) post-quantum cryptography algorithm.

The simulation is built using `qunetsim` and demonstrates a secure key exchange between a classical node and a quantum node, facilitated by a middleware node.

## Features

- **BB84 Protocol**: Implements the BB84 protocol for quantum key distribution, including mechanisms for sifting, error estimation, and privacy amplification.
- **ML-KEM Protocol**: Utilizes the `quantcrypt` library to implement the ML-KEM-1024 key encapsulation mechanism.
- **Hybrid Key Exchange**: Demonstrates a fusion of the two protocols where a classical and quantum node can establish a shared secret key.
- **Network Simulation**: Uses `qunetsim` to simulate the quantum and classical network components.

## Requirements

- Python 3.7+
- Dependencies can be found in `requirements.txt`.

## Installation

1. Clone the repository:

2. Install the required packages:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the simulation, execute the `main.py` script:

```bash
python main.py
```

The script will set up a network with three nodes: a classical node, a middleware node, and a quantum node. It will then run the hybrid key exchange protocol and print the derived shared key from the perspectives of the classical and quantum nodes.

## Project Structure

- `main.py`: The main entry point for the simulation. It sets up the network and runs the protocols.
- `protocols/`:
  - `bb84.py`: Contains the implementation of the BB84 protocol.
  - `mlkem.py`: Contains the implementation of the ML-KEM encapsulation and decapsulation logic.
  - `bb84_mlkem_fusion_demo.py`: Defines the high-level logic for the classical, middleware, and quantum nodes in the hybrid protocol.
- `requirements.txt`: A list of the Python packages required for the project.
- `.gitignore`: Standard Python gitignore file.
- `README.md`: This file.
