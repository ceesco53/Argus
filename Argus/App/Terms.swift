import SwiftUI

/// The terms everyone must accept before Argus runs. The README carries the same text.
enum Terms {
    /// Bump to ask everyone to accept changed terms.
    static let version = 1
    static let effectiveDate = "October 26, 2026"
    static let title = "Argus Disclaimer and Terms of Use"
    static let preamble = "PLEASE READ THESE TERMS CAREFULLY. THEY FORM A BINDING AGREEMENT BETWEEN YOU AND THE AUTHOR OF ARGUS. BY INSTALLING, OPENING OR USING ARGUS, OR BY SELECTING “AGREE”, YOU ACCEPT THESE TERMS. IF YOU DO NOT AGREE, DO NOT INSTALL OR USE ARGUS."

    struct Section: Identifiable {
        let heading: String
        let body: String
        var id: String { heading }
    }

    static let sections: [Section] = [
        Section(heading: "1. AI-Generated Software",
                body: "Argus was “vibe coded”: it was written largely by Claude, an artificial-intelligence model made by Anthropic, at the direction of its author and with limited human review. It may contain errors, security vulnerabilities and behavior that no one intended or anticipated. Argus is an independent project; it is not made, reviewed, endorsed or supported by Anthropic."),
        Section(heading: "2. No Warranty",
                body: "ARGUS IS PROVIDED “AS IS” AND “AS AVAILABLE”, WITH ALL FAULTS AND WITHOUT WARRANTY OF ANY KIND, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING ANY WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, NON-INFRINGEMENT, ACCURACY, SECURITY OR UNINTERRUPTED OR ERROR-FREE OPERATION. The author does not warrant that Argus will protect your Mac, or that it will block or allow any particular connection."),
        Section(heading: "3. Assumption of Risk",
                body: "Argus installs a system network filter that inspects, holds, allows and blocks network traffic for every program on your Mac. You understand that using it may, among other things, interrupt or disable internet and network access; break apps, services and updates; cause loss or corruption of data; expose information or fail to protect it; interfere with security software or emergency communications; and require you to reinstall software or macOS. You use Argus entirely at your own risk and are solely responsible for the results, including backing up your data and every connection Argus allows or blocks."),
        Section(heading: "4. Limitation of Liability",
                body: "TO THE FULLEST EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE AUTHOR OR ANY CONTRIBUTOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY OF ANY KIND, WHETHER DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY OR PUNITIVE, INCLUDING LOSS OF DATA, PROFITS, REVENUE, BUSINESS, GOODWILL OR USE, OR COMPUTER FAILURE OR MALFUNCTION, ARISING FROM OR RELATED TO ARGUS OR ITS USE, WHETHER IN CONTRACT, TORT (INCLUDING NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. WHERE LIABILITY CANNOT BE EXCLUDED, IT IS LIMITED TO THE AMOUNT YOU PAID FOR ARGUS, IF ANY."),
        Section(heading: "5. Not Professional or Security Advice",
                body: "Argus’s suggestions, ratings, blocklists, reports and other output are for information only and may be wrong. Do not rely on Argus as your only protection, or for any safety-critical, medical, legal, financial, compliance or emergency purpose."),
        Section(heading: "6. Indemnification",
                body: "You agree to indemnify, defend and hold harmless the author and all contributors from and against any claim, loss, liability, damage or expense (including reasonable legal fees) arising from your use or misuse of Argus or your breach of these terms."),
        Section(heading: "7. Lawful Use",
                body: "You are solely responsible for complying with every law that applies to you, including laws on monitoring network traffic and capturing packets. Use Argus only on devices and networks you own or are authorized to monitor."),
        Section(heading: "8. General",
                body: "These terms supplement the MIT License under which Argus’s source code is distributed and do not limit the rights that license grants. If any provision is held unenforceable, it shall be enforced to the maximum extent permissible and the remaining provisions shall remain in full force and effect. If these terms change, Argus will ask you to accept them again before it runs. By agreeing, you confirm that you have read and understood these terms and are legally able to accept them."),
    ]

    static let acceptedVersionKey = "acceptedTermsVersion"
    private static let acceptedDateKey = "acceptedTermsDate"

    static var isAccepted: Bool { UserDefaults.standard.integer(forKey: acceptedVersionKey) >= version }
    static var acceptedDate: Date? { UserDefaults.standard.object(forKey: acceptedDateKey) as? Date }

    static func accept() {
        UserDefaults.standard.set(version, forKey: acceptedVersionKey)
        UserDefaults.standard.set(Date(), forKey: acceptedDateKey)
    }
}

/// The terms, either as the first-run agreement (Argus quits unless it's accepted) or for reading later.
struct TermsView: View {
    var requiresAgreement = false
    var onAgree: () -> Void = {}
    var onDecline: () -> Void = {}
    @State private var agreed = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 14) {
                MascotView(size: 60).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text(requiresAgreement ? "Before you use Argus" : Terms.title).font(.title2.weight(.semibold))
                    Text(requiresAgreement
                         ? "Argus won’t run until you read and accept these terms."
                         : "Version \(Terms.version) · Effective \(Terms.effectiveDate)")
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(20)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if requiresAgreement {
                        Text("\(Terms.title) · Version \(Terms.version) · Effective \(Terms.effectiveDate)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text(Terms.preamble).font(.callout.weight(.semibold))
                    ForEach(Terms.sections) { section in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(section.heading).font(.headline)
                            Text(section.body).font(.callout)
                        }
                    }
                }
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
            }
            Divider()
            HStack(spacing: 12) {
                if requiresAgreement {
                    Toggle("I have read and agree to the Argus Terms of Use", isOn: $agreed)
                        .toggleStyle(.checkbox)
                    Spacer()
                    Button("Quit Argus", role: .cancel) { onDecline() }
                        .keyboardShortcut(.cancelAction)
                    Button("Agree and Continue") { onAgree() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!agreed)
                } else {
                    if let date = Terms.acceptedDate {
                        Text("You accepted these terms on \(date.formatted(date: .long, time: .shortened)).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                }
            }
            .padding(16)
        }
        .frame(width: 640, height: 660)
    }
}
