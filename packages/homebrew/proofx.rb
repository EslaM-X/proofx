# typed: false
# frozen_string_literal: true

# ProofX — Evidence Infrastructure for Software
# https://github.com/EslaM-X/proofx

class Proofx < Formula
  desc "Evidence Infrastructure for Software — CLI + GitHub Action + public verification"
  homepage "https://github.com/EslaM-X/proofx"
  version "0.3.0"
  license "MIT"
  on_macos do
    on_intel do
      url "https://github.com/EslaM-X/proofx/releases/download/v#{version}/proofx-darwin-amd64"
      sha256 "adde1afb7643a4ade1f2d23ac517000bda5a43adea16392ee1d936d6c127a78b"
    end
    on_arm do
      url "https://github.com/EslaM-X/proofx/releases/download/v#{version}/proofx-darwin-arm64"
      sha256 "ad3643e5f949741cb76c7bb5a289d06af0a52a6738ecbe8309ed3062c2873e95"
    end
  end
  on_linux do
    on_intel do
      url "https://github.com/EslaM-X/proofx/releases/download/v#{version}/proofx-linux-amd64"
      sha256 "ce23c531cabc51f81f63fd54fa9aa1de245f421ecefdf2fa1ae31d6eb58bd65c"
    end
    on_arm do
      url "https://github.com/EslaM-X/proofx/releases/download/v#{version}/proofx-linux-arm64"
      sha256 "1bf192a8d5cdaf68df3d4cf8c73185d1a9f94491c620c9d047b879e0155e99f9"
    end
  end

  def install
    bin.install "proofx"
  end

  test do
    assert_match "proofx #{version}", shell_output("#{bin}/proofx --version")
  end
end
