from pathlib import Path

import pytest

from actionsieve.providers import ParseError
from actionsieve.providers.jenkins import JenkinsProvider


@pytest.fixture
def provider() -> JenkinsProvider:
    return JenkinsProvider()


def _write_jenkinsfile(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "Jenkinsfile"
    p.write_text(content)
    return p


class TestDetect:
    def test_detects_jenkinsfile(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        (tmp_path / "Jenkinsfile").write_text("pipeline { }")
        assert provider.detect(tmp_path) is True

    def test_detects_groovy_extension(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        (tmp_path / "Jenkinsfile.groovy").write_text("pipeline { }")
        assert provider.detect(tmp_path) is True

    def test_rejects_non_jenkins_repo(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        assert provider.detect(tmp_path) is False


class TestFindFiles:
    def test_finds_jenkinsfile(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        (tmp_path / "Jenkinsfile").write_text("pipeline { }")
        files = provider.find_files(tmp_path)
        assert len(files) == 1

    def test_empty_when_no_file(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        assert provider.find_files(tmp_path) == []


class TestParseBasic:
    def test_parses_simple_pipeline(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo hello'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert wf.platform == "jenkins"
        assert len(wf.jobs) == 1
        assert wf.jobs[0].id == "Build"
        assert wf.jobs[0].steps[0].shell_command == "echo hello"

    def test_multiple_stages(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        stage('Test') {
            steps {
                sh 'make test'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 2
        assert wf.jobs[0].id == "Build"
        assert wf.jobs[1].id == "Test"

    def test_double_quoted_command(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh "echo build"
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].shell_command == "echo build"

    def test_triple_quoted_command(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh '''
                    echo multi
                    echo line
                '''
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert "echo multi" in (wf.jobs[0].steps[0].shell_command or "")

    def test_bat_step(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                bat 'dir'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].shell_command == "dir"
        assert wf.jobs[0].steps[0].name == "bat"

    def test_powershell_step(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                powershell 'Get-Process'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].steps[0].shell_command == "Get-Process"


class TestAgent:
    def test_agent_any_is_self_hosted(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo hi'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True

    def test_agent_label(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent { label 'linux-build' }
    stages {
        stage('Build') {
            steps {
                sh 'echo hi'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True
        assert "linux-build" in wf.jobs[0].runner.labels

    def test_agent_docker(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent { docker { image 'node:18' } }
    stages {
        stage('Build') {
            steps {
                sh 'npm install'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is False
        assert "node:18" in wf.jobs[0].runner.labels


class TestTriggers:
    def test_default_push_trigger(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo hi'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert len(wf.triggers) == 1
        assert wf.triggers[0].event == "push"
        assert wf.triggers[0].is_privileged is True

    def test_cron_trigger(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    triggers {
        cron('H/15 * * * *')
    }
    stages {
        stage('Build') {
            steps {
                sh 'echo hi'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        cron = next((t for t in wf.triggers if t.event == "cron"), None)
        assert cron is not None
        assert cron.is_privileged is True

    def test_multibranch_detected(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh "echo building ${env.BRANCH_NAME}"
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        mb = next((t for t in wf.triggers if t.event == "multibranch"), None)
        assert mb is not None
        assert mb.is_fork_reachable is True


class TestExpressions:
    def test_interpolation_detected(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh "echo ${params.USER_INPUT}"
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1
        assert tainted[0].context_path == "params.USER_INPUT"

    def test_safe_variable_not_tainted(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh "echo ${env.BUILD_NUMBER}"
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) == 0

    def test_change_title_tainted(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh "echo ${env.CHANGE_TITLE}"
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1


class TestLibraries:
    def test_library_detected(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
@Library('my-shared-lib@main') _
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo hi'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        lib_steps = [s for s in wf.jobs[0].steps if s.type == "action"]
        assert len(lib_steps) >= 1
        assert lib_steps[0].action_ref is not None
        assert lib_steps[0].action_ref.name == "my-shared-lib"
        assert lib_steps[0].action_ref.ref == "main"


class TestCredentials:
    def test_credentials_detected(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {
                    sh 'deploy --token $TOKEN'
                }
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert "deploy-token" in wf.jobs[0].secrets_referenced


class TestEnvironment:
    def test_env_block_parsed(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    environment {
        CC = 'clang'
        DEBUG = 'true'
    }
    stages {
        stage('Build') {
            steps {
                sh 'echo hi'
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert wf.env.get("CC") == "clang"
        assert wf.env.get("DEBUG") == "true"


class TestEdgeCases:
    def test_scripted_pipeline_parses(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(tmp_path, "node { sh 'echo hi' }")
        wf = provider.parse(p)
        assert wf.platform == "jenkins"
        assert len(wf.jobs) == 1
        assert wf.jobs[0].steps[0].shell_command == "echo hi"

    def test_empty_file_no_crash(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(tmp_path, "// empty")
        wf = provider.parse(p)
        assert wf.jobs == []

    def test_file_size_limit(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(tmp_path, "x" * (1_048_577))
        with pytest.raises(ParseError, match="exceeds"):
            provider.parse(p)

    def test_expression_syntax(self, provider: JenkinsProvider) -> None:
        syntax = provider.expression_syntax()
        assert syntax.delimiters == ("${", "}")
        assert "params" in syntax.context_roots


class TestScriptedPipeline:
    def test_scripted_with_stages(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
node('linux') {
    stage('Build') {
        sh 'make build'
    }
    stage('Test') {
        sh 'make test'
    }
}
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 2
        assert wf.jobs[0].id == "Build"
        assert wf.jobs[1].id == "Test"
        assert wf.jobs[0].steps[0].shell_command == "make build"

    def test_scripted_agent_label(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(tmp_path, "node('my-agent') { sh 'echo hi' }")
        wf = provider.parse(p)
        assert wf.jobs[0].runner.is_self_hosted is True
        assert "my-agent" in wf.jobs[0].runner.labels

    def test_scripted_no_stages(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
node {
    sh 'echo hello'
    sh "deploy ${params.TARGET}"
}
""",
        )
        wf = provider.parse(p)
        assert len(wf.jobs) == 1
        assert wf.jobs[0].id == "pipeline"
        assert len(wf.jobs[0].steps) == 2

    def test_scripted_tainted_expression(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
node {
    stage('Deploy') {
        sh "deploy ${params.TARGET}"
    }
}
""",
        )
        wf = provider.parse(p)
        step = wf.jobs[0].steps[0]
        tainted = [e for e in step.expressions if e.is_tainted]
        assert len(tainted) >= 1
        assert tainted[0].context_path == "params.TARGET"

    def test_scripted_credentials(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
node {
    stage('Deploy') {
        withCredentials([string(credentialsId: 'my-token', variable: 'T')]) {
            sh 'deploy --token $T'
        }
    }
}
""",
        )
        wf = provider.parse(p)
        assert "my-token" in wf.jobs[0].secrets_referenced


class TestScriptBlock:
    def test_script_block_shell_detected(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo basic'
                script {
                    sh "deploy ${params.TARGET}"
                }
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        steps = wf.jobs[0].steps
        shell_steps = [s for s in steps if s.type == "shell"]
        assert len(shell_steps) == 2
        assert shell_steps[0].shell_command == "echo basic"
        assert shell_steps[1].shell_command == "deploy ${params.TARGET}"

    def test_script_block_tainted(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                script {
                    sh "echo ${env.CHANGE_TITLE}"
                }
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        shell_steps = [s for s in wf.jobs[0].steps if s.type == "shell"]
        tainted = [e for s in shell_steps for e in s.expressions if e.is_tainted]
        assert len(tainted) >= 1

    def test_sh_named_arg(self, provider: JenkinsProvider, tmp_path: Path) -> None:
        p = _write_jenkinsfile(
            tmp_path,
            """\
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh(script: "echo ${params.X}", returnStdout: true)
            }
        }
    }
}
""",
        )
        wf = provider.parse(p)
        steps = [s for s in wf.jobs[0].steps if s.type == "shell"]
        assert len(steps) == 1
        assert "params.X" in (steps[0].shell_command or "")
