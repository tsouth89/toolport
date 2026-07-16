cask "toolport" do
  version "1.9.1"

  on_arm do
    sha256 "0104c38abd8597c487a9de52ae6f43bc35e278a8cfdaa0205ce0a6c409670f5b"
    url "https://github.com/tsouth89/toolport/releases/download/v#{version}/Toolport_aarch64-apple-darwin.dmg",
        verified: "github.com/tsouth89/toolport/"
  end
  on_intel do
    sha256 "63df2eb77a1923f4457a2c034747a0d7a970c7d2ba6cee80a9e612014732dc08"
    url "https://github.com/tsouth89/toolport/releases/download/v#{version}/Toolport_x86_64-apple-darwin.dmg",
        verified: "github.com/tsouth89/toolport/"
  end

  name "Toolport"
  desc "One local gateway for every MCP server, shared by every AI client"
  homepage "https://toolport.app/"

  # The updater ships new versions in-app; livecheck tracks the GitHub releases so
  # `brew upgrade` also works for anyone who prefers it.
  livecheck do
    url :url
    strategy :github_latest
  end

  app "Toolport.app"

  # The gateway is a nested helper the app manages; no separate binaries to link.
  zap trash: [
    "~/Library/Application Support/Conduit",
    "~/Library/Caches/com.tsout.conduit",
    "~/Library/HTTPStorages/com.tsout.conduit",
    "~/Library/Preferences/com.tsout.conduit.plist",
    "~/Library/Saved Application State/com.tsout.conduit.savedState",
  ]
end
