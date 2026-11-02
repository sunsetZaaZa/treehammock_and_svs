using Shouldly;

namespace treehammock.Tests.Unit;

public class GitLabReleasePipelineTests
{
    [Fact]
    public void Root_dispatcher_exposes_release_child_pipeline_with_its_own_trigger()
    {
        string root = File.ReadAllText(ProjectFile(".gitlab-ci.yml"));

        root.ShouldContain("trigger-release-pipeline:");
        root.ShouldContain("local: .gitlab/ci/pipelines/release.yml");
        root.ShouldContain("RUN_RELEASE_PIPELINE == \"true\"");
        root.ShouldContain("$CI_COMMIT_TAG =~ /^v");
        root.ShouldContain("strategy: depend");
        root.ShouldContain("pipeline_variables: true");
        root.ShouldNotContain("release-gate:");
    }

    [Fact]
    public void Release_child_pipeline_runs_all_release_gates_before_packaging()
    {
        string release = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "release.yml"));

        release.ShouldContain("release-preflight:");
        release.ShouldContain("release-dotnet-unit-gate:");
        release.ShouldContain("release-dotnet-integration-gate:");
        release.ShouldContain("release-dotnet-sql-gate:");
        release.ShouldContain("release-docker-direct-gate:");
        release.ShouldContain("release-docker-proxy-gate:");
        release.ShouldContain("release-docker-system-gate:");
        release.ShouldContain("release-package-api:");
        release.ShouldContain("release-upload-assets:");
        release.ShouldContain("create-gitlab-release:");
        release.ShouldContain("./eng/dotnet-unit-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/dotnet-integration-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/sql-contracts.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/docker-http-contracts-direct.sh");
        release.ShouldContain("./eng/docker-http-contracts-proxy.sh");
        release.ShouldContain("./eng/docker-system-stack-tests.sh");
        release.ShouldContain("release-dotnet-unit-gate");
        release.ShouldContain("release-dotnet-integration-gate");
        release.ShouldContain("release-dotnet-sql-gate");
        release.ShouldContain("$CI_PIPELINE_SOURCE == \"parent_pipeline\"");
    }

    [Fact]
    public void Release_pipeline_publishes_versioned_package_assets()
    {
        string release = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "release.yml"));

        release.ShouldContain("RELEASE_PACKAGE_NAME: \"treehammock-api\"");
        release.ShouldContain("python3 eng/release_artifacts.py build --output artifacts/release");
        release.ShouldContain("release-publication-summary:");
        release.ShouldContain("curl --fail --header \"JOB-TOKEN: ${CI_JOB_TOKEN}\"");
        release.ShouldContain("packages/generic/${RELEASE_PACKAGE_NAME}/${RELEASE_PACKAGE_VERSION}");
    }

    [Fact]
    public void Release_pipeline_has_opt_in_container_registry_jobs()
    {
        string release = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "release.yml"));

        release.ShouldContain("PUBLISH_GITLAB_REGISTRY: \"false\"");
        release.ShouldContain("PUBLISH_SELF_HOSTED_REGISTRY: \"false\"");
        release.ShouldContain("PUBLISH_DOCKERHUB: \"false\"");
        release.ShouldContain("PUBLISH_AWS_ECR: \"false\"");
        release.ShouldContain("PUSH_LATEST_FOR_STABLE: \"true\"");

        release.ShouldContain("release-container-gitlab-registry:");
        release.ShouldContain("release-container-self-hosted-registry:");
        release.ShouldContain("release-container-dockerhub:");
        release.ShouldContain("release-container-aws-ecr:");
        release.ShouldNotContain("release-container-image:");

        release.ShouldContain("REGISTRY_KIND: gitlab");
        release.ShouldContain("REGISTRY_KIND: generic");
        release.ShouldContain("REGISTRY_KIND: dockerhub");
        release.ShouldContain("REGISTRY_KIND: aws-ecr");
        release.ShouldContain("./eng/release-container-publish.sh");

        release.ShouldContain("$PUBLISH_GITLAB_REGISTRY == \"true\"");
        release.ShouldContain("$PUBLISH_SELF_HOSTED_REGISTRY == \"true\"");
        release.ShouldContain("$PUBLISH_DOCKERHUB == \"true\"");
        release.ShouldContain("$PUBLISH_AWS_ECR == \"true\"");
    }

    [Fact]
    public void Release_pipeline_supports_aws_ecr_oidc_and_optional_registry_needs()
    {
        string release = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "release.yml"));

        release.ShouldContain("id_tokens:");
        release.ShouldContain("GITLAB_OIDC_TOKEN:");
        release.ShouldContain("AWS_WEB_IDENTITY_TOKEN_FILE");
        release.ShouldContain("AWS_ROLE_SESSION_NAME");
        release.ShouldContain("apk add --no-cache python3 py3-yaml bash skopeo aws-cli");
        release.ShouldContain("job: release-container-aws-ecr");
        release.ShouldContain("optional: true");
        release.ShouldContain("artifacts: false");
    }

    [Fact]
    public void Release_container_publish_script_supports_all_required_registry_targets()
    {
        string script = File.ReadAllText(ProjectFile("eng", "release-container-publish.sh"));

        script.ShouldContain("release_artifacts.py promote");
        script.ShouldNotContain("docker build");
        string publisher = File.ReadAllText(ProjectFile("eng", "release_artifacts.py"));
        publisher.ShouldContain("CI_REGISTRY_PASSWORD");
        publisher.ShouldContain("SELF_HOSTED_REGISTRY_PASSWORD");
        publisher.ShouldContain("DOCKERHUB_TOKEN");
        publisher.ShouldContain("get-login-password");
        publisher.ShouldContain("--preserve-digests");
    }

    [Fact]
    public void Release_creation_uses_gitlab_release_assets()
    {
        string release = File.ReadAllText(ProjectFile(".gitlab", "ci", "pipelines", "release.yml"));

        release.ShouldContain("image: registry.gitlab.com/gitlab-org/cli:latest");
        release.ShouldContain("release:");
        release.ShouldContain("name: \"Treehammock $CI_COMMIT_TAG\"");
        release.ShouldContain("tag_name: \"$CI_COMMIT_TAG\"");
        release.ShouldContain("assets:");
        release.ShouldContain("API publish archive");
        release.ShouldContain("API publish archive SHA256");
        release.ShouldContain("link_type: \"package\"");
        release.ShouldContain("Container images are promoted from one tested OCI artifact only to enabled targets");
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
