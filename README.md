<p align="center">
<img width="200" src="https://github.com/rayston92/graph_bed/blob/e3b2c938fc5b17d68531f69178908afb16266e6a/img/onekey_logo_badge_border.png?raw=trueg"/>
</p>

---

[![Github Stars](https://img.shields.io/github/stars/OneKeyHQ/firmware-classic1s?t&logo=github&style=for-the-badge&labelColor=000)](https://github.com/OneKeyHQ/firmware-classic1s/stargazers)
[![Version](https://img.shields.io/github/release/OneKeyHQ/firmware-classic1s.svg?style=for-the-badge&labelColor=000)](https://github.com/OneKeyHQ/firmware-classic1s/releases)
[![Contributors](https://img.shields.io/github/contributors-anon/OneKeyHQ/firmware-classic1s?style=for-the-badge&labelColor=000)](https://github.com/OneKeyHQ/firmware-classic1s/graphs/contributors)
[![Last Commit](https://img.shields.io/github/last-commit/OneKeyHQ/firmware-classic1s.svg?style=for-the-badge&labelColor=000)](https://github.com/OneKeyHQ/firmware-classic1s/commits/onekey)
[![Issues](https://img.shields.io/github/issues-raw/OneKeyHQ/firmware-classic1s.svg?style=for-the-badge&labelColor=000)](https://github.com/OneKeyHQ/firmware-classic1s/issues?q=is%3Aissue+is%3Aopen)
[![Pull Requests](https://img.shields.io/github/issues-pr-raw/OneKeyHQ/firmware-classic1s.svg?style=for-the-badge&labelColor=000)](https://github.com/OneKeyHQ/firmware-classic1s/pulls?q=is%3Apr+is%3Aopen)
[![Discord](https://img.shields.io/discord/868309113942196295?style=for-the-badge&labelColor=000)](https://discord.gg/onekey)
[![Twitter Follow](https://img.shields.io/twitter/follow/OneKeyHQ?style=for-the-badge&labelColor=000)](https://twitter.com/OneKeyHQ)

## Community & Support

- **[Community Forum](https://github.com/orgs/OneKeyHQ/discussions)**: Best for help with building and discussing best practices.
- **[GitHub Issues](https://github.com/OneKeyHQ/firmware-classic1s/issues)**: Report bugs and errors encountered while using OneKey.

## 🚀 Getting Started

1. **Install Nix**: Follow the instructions [here](https://nixos.org/download.html).
2. **Clone the Repository**:
   ```sh
   git clone https://github.com/OneKeyHQ/firmware-classic1s
   cd firmware-classic1s
   nix-shell
   poetry install
   ```
3. **Build the Project**:
   ```sh
   cd legacy
   export EMULATOR=1 DEBUG_LINK=1 DEBUG_LOG=1
   poetry run make vendor
   poetry run ./script/setup
   poetry run ./script/cibuild
   ```
4. **Start the Emulator**:
   ```sh
   ./firmware/classic*Stable*.bin
   ```
5. **Install the Command Line Client**:
   ```sh
   cd python && poetry run python3 -m pip install .
   ```

## 🔒 Security

- Read the [Bug Bounty Rules](https://github.com/OneKeyHQ/app-monorepo/blob/onekey/docs/BUG_RULES.md) for details on our security policies.
- Report suspected security vulnerabilities privately to dev@onekey.so.
- Do not create public issues for suspected vulnerabilities.

As an open-source project, we offer rewards to white hat hackers who disclose vulnerabilities promptly.

## License

Please check License.md for details