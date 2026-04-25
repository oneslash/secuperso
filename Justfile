set shell := ["bash", "-uc"]

default:
    @just --list

xcodegen:
    xcodegen generate

build-debug:
    xcodebuild -project SecuPerso.xcodeproj -scheme SecuPerso-Debug -destination 'platform=macOS' build

test:
    xcodebuild -project SecuPerso.xcodeproj -scheme SecuPerso-Debug -destination 'platform=macOS' test

build-release:
    xcodebuild -project SecuPerso.xcodeproj -scheme SecuPerso-Release -destination 'platform=macOS' build

package-builds:
    for pkg in SecuPersoDomain SecuPersoData SecuPersoFeatures SecuPersoUI; do \
      swift build --package-path Packages/$pkg; \
    done

select-xcode-full:
    xcode-select -s /Applications/Xcode.app/Contents/Developer
