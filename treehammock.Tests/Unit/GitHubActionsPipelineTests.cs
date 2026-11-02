using Shouldly;

namespace treehammock.Tests.Unit;

public class GitHubActionsPipelineTests
{
    [Fact]
    public void Github_ci_runs_fast_validation_by_default_and_exposes_manual_heavy_lanes()
    {
        string ci = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-ci.yml"));

        ci.ShouldContain("name: Treehammock CI");
        ci.ShouldContain("pull_request:");
        ci.ShouldContain("push:");
        ci.ShouldContain("workflow_dispatch:");
        ci.ShouldContain("permissions:");
        ci.ShouldContain("contents: read");
        ci.ShouldContain("dotnet-unit-tests:");
        ci.ShouldContain("dotnet-integration-tests:");
        ci.ShouldContain("./eng/dotnet-unit-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        ci.ShouldContain("./eng/dotnet-integration-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        ci.ShouldContain("actions/checkout@v6");
        ci.ShouldContain("actions/setup-dotnet@v5");
        ci.ShouldContain("actions/upload-artifact@v7");
        ci.ShouldContain("dotnet-version: 8.0.x");
        ci.ShouldContain("cache-dependency-path:");

        ci.ShouldContain("dotnet-sql-contracts:");
        ci.ShouldContain("docker-direct-integration:");
        ci.ShouldContain("docker-proxy-integration:");
        ci.ShouldContain("docker-system-stack:");
        ci.ShouldContain("github.event.inputs.lane == 'sql'");
        ci.ShouldContain("github.event.inputs.lane == 'docker-direct'");
        ci.ShouldContain("github.event.inputs.lane == 'docker-proxy'");
        ci.ShouldContain("github.event.inputs.lane == 'docker-system'");
        ci.ShouldContain("github.event_name == 'workflow_dispatch'");
        ci.ShouldContain("postgres:16");
        ci.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS: \"true\"");
        ci.ShouldContain("./eng/docker-host-system-stack-tests.sh");
        ci.ShouldContain("docker-compose.local-system.yml");
    }

    [Fact]
    public void Github_release_workflow_defaults_to_1_0_0_and_runs_all_release_gates_before_packaging()
    {
        string release = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-release.yml"));

        release.ShouldContain("name: Treehammock Release");
        release.ShouldContain("group: treehammock-release-${{ github.workflow }}-${{ github.ref }}-${{ github.ref_name }}");
        release.ShouldContain("push:");
        release.ShouldContain("branches:");
        release.ShouldContain("- main");
        release.ShouldContain("default: v1.0.0");
        release.ShouldNotContain("tags:");
        release.ShouldNotContain("v*.*.*");
        release.ShouldContain("permissions:");
        release.ShouldContain("contents: write");
        release.ShouldContain("packages: write");

        release.ShouldContain("release-preflight:");
        release.ShouldContain("run: python3 eng/release-metadata.py");
        release.ShouldContain("INPUT_RELEASE_TAG: ${{ inputs.release_tag }}");
        release.ShouldContain("INPUT_TARGET_REF: ${{ inputs.target_ref }}");
        release.ShouldContain("contents: read");
        release.ShouldContain("persist-credentials: false");
        release.ShouldContain("needs.release-preflight.outputs.publish_ghcr == 'true'");
        release.ShouldContain("needs.release-preflight.outputs.create_release == 'true'");
        release.ShouldContain("ref: main");
        release.ShouldContain("if: ${{ needs.release-preflight.outputs.should_release == 'true' }}");
        release.ShouldContain("release-dotnet-unit-gate:");
        release.ShouldContain("release-dotnet-integration-gate:");
        release.ShouldContain("release-dotnet-sql-gate:");
        release.ShouldContain("release-docker-direct-gate:");
        release.ShouldContain("release-docker-proxy-gate:");
        release.ShouldContain("release-docker-system-gate:");
        release.ShouldContain("release-package-api:");
        release.ShouldContain("create-github-release:");

        release.ShouldContain("./eng/dotnet-unit-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/dotnet-integration-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/sql-contracts.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/docker-http-contracts-direct.sh");
        release.ShouldContain("./eng/docker-http-contracts-proxy.sh");
        release.ShouldContain("./eng/docker-host-system-stack-tests.sh");
        release.ShouldContain("docker-compose.local-system.yml");

        release.ShouldContain("release-dotnet-unit-gate");
        release.ShouldContain("release-dotnet-integration-gate");
        release.ShouldContain("release-dotnet-sql-gate");
        release.ShouldContain("release-docker-direct-gate");
        release.ShouldContain("release-docker-proxy-gate");
        release.ShouldContain("release-docker-system-gate");
    }

    [Fact]
    public void Github_release_workflow_publishes_versioned_assets_and_can_create_the_github_release()
    {
        string release = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-release.yml"));

        release.ShouldContain("RELEASE_PACKAGE_NAME: treehammock-api");
        release.ShouldContain("python3 eng/release_artifacts.py build --output artifacts/release");
        release.ShouldContain("python3 eng/release_artifacts.py verify");
        release.ShouldContain("release-manifest.json");
        release.ShouldContain("release-summary.json");
        release.ShouldContain("actions/download-artifact@v7");
        release.ShouldContain("GH_REPO: ${{ github.repository }}");
        release.ShouldContain("gh release view \"$RELEASE_TAG\" --repo \"$GH_REPO\"");
        release.ShouldContain("gh \"${release_args[@]}\"");
        release.ShouldContain("--title \"Tree Hammock ${RELEASE_TAG}\"");
        release.ShouldContain("--generate-notes");
        release.ShouldContain("RELEASE_MODE: ${{ needs.release-preflight.outputs.release_mode }}");
        release.ShouldContain("if [ \"$RELEASE_MODE\" != \"tag\" ]; then");
        release.ShouldNotContain("release_mode=\"tag\"");
        release.ShouldContain("--target \"$CHECKOUT_REF\"");
    }

    [Fact]
    public void Github_release_workflow_is_pinned_to_v1_0_0_initial_main_commit_only()
    {
        string release = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-release.yml"));
        string metadata = File.ReadAllText(ProjectFile("eng", "release-metadata.py"));

        release.ShouldContain("default: v1.0.0");
        release.ShouldContain("ref: main");
        release.ShouldContain("run: python3 eng/release-metadata.py");
        release.ShouldContain("if: ${{ needs.release-preflight.outputs.should_release == 'true' }}");
        metadata.ShouldContain("Release workflow is pinned to v1.0.0 only.");
        metadata.ShouldContain("Release v1.0.0 only runs from the initial commit to main.");
        metadata.ShouldContain("Manual v1.0.0 release must target the initial commit to main.");
        metadata.ShouldContain("GitHub Release already exists.");
        metadata.ShouldContain("Git tag already exists.");
        metadata.ShouldContain("'--verify', '--end-of-options'");
        metadata.ShouldNotContain("shell=True");
    }

    [Fact]
    public void Github_release_workflow_can_publish_opt_in_ghcr_image()
    {
        string release = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-release.yml"));
        string script = File.ReadAllText(ProjectFile("eng", "release-container-publish.sh"));

        release.ShouldContain("release-ghcr-image:");
        release.ShouldContain("publish_ghcr");
        release.ShouldContain("PUBLISH_GHCR: ${{ vars.PUBLISH_GHCR }}");
        release.ShouldContain("REGISTRY_KIND: github");
        release.ShouldContain("GITHUB_CONTAINER_REGISTRY=\"ghcr.io\"");
        release.ShouldContain("GITHUB_CONTAINER_IMAGE=\"ghcr.io/${repository_lower}\"");
        release.ShouldContain("name: treehammock-ghcr-image");
        release.ShouldContain("./eng/release-container-publish.sh");

        script.ShouldContain("release_artifacts.py promote");
        script.ShouldNotContain("docker build");
        string publisher = File.ReadAllText(ProjectFile("eng", "release_artifacts.py"));
        publisher.ShouldContain("GITHUB_CONTAINER_IMAGE");
        publisher.ShouldContain("GITHUB_TOKEN");
        publisher.ShouldContain("--preserve-digests");
    }

    [Fact]
    public void Development_defaults_are_distinct_from_canonical_release_properties()
    {
        string props = File.ReadAllText(ProjectFile("Directory.Build.props"));

        props.ShouldContain("<Product>Raptor Balcony</Product>");
        props.ShouldContain(">1.0.0</VersionPrefix>");
        props.ShouldContain(">1.0.0</PackageVersion>");
        props.ShouldContain(">1.0.0.0</AssemblyVersion>");
        props.ShouldContain(">1.0.0.0</FileVersion>");
        props.ShouldContain(">1.0.0-dev</InformationalVersion>");
        props.ShouldContain("'$(GITHUB_ACTIONS)' == 'true'");
        props.ShouldContain("'$(GITLAB_CI)' == 'true'");
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }
}
