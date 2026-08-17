# typed: false
# frozen_string_literal: true

# ProofX — Evidence Infrastructure for Software
# https://github.com/EslaM-X/proofx

class Proofx < Formula
  desc "Evidence Infrastructure for Software — CLI + GitHub Action + public verification"
  homepage "https://github.com/EslaM-X/proofx"
  version "0.2.1"
  license "MIT"
  on_macos do
    on_intel do
      url "https://github.com/EslaM-X/proofx/releases/download/v#{version}/proofx-darwin-amd64"
      sha256 "4671e9081ea461a5fd5fc9682d2afe7ce15eb08c23bbf2388b34a5fa61960e98"
    end
    on_arm do
      url "https://github.com/EslaM-X/proofx/releases/download/v#{version}/proofx-darwin-arm64"
      sha256 "3e925b69f6feedb1bc9c92b218709046f9faeaf298481a0b6aec10d9342b73d9"
    end
  end
  on_linux do
    on_intel do
      url "https://github.com/EslaM-X/proofx/releases/download/v#{version}/proofx-linux-amd64"
      sha256 "cb23dad2cfeed52111454d67d5a951310d782fbbcef60ef9dccacbc0c1989ce3"
    end
    on_arm do
      url "https://github.com/EslaM-X/proofx/releases/download/v#{version}/proofx-linux-arm64"
      sha256 "fe1189d83b58e4a60e8e9946f4bc8bc84b557322c71e5f03a1e5b05b1c1c03ae"
    end
  end

  def install
    bin.install "proofx"
  end

  test do
    assert_match "proofx #{version}", shell_output("#{bin}/proofx --version")
  end
end
