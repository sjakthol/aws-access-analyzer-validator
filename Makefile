# Mapping from long region names to shorter ones that is to be
# used in the stack names
AWS_eu-north-1_PREFIX = en1
AWS_eu-west-1_PREFIX = ew1
AWS_us-east-1_PREFIX = ue1

# Some defaults
AWS ?= aws
AWS_REGION ?= eu-west-1

AWS_CMD := $(AWS) --region $(AWS_REGION)

STACK_NAME_PREFIX := $(AWS_$(AWS_REGION)_PREFIX)-aa-validator

TAGS ?= Project=$(STACK_NAME_PREFIX)

# Generic deployment and teardown targets
deploy-%:
	$(AWS_CMD) cloudformation deploy \
		--stack-name $(STACK_NAME_PREFIX)-$* \
		--tags $(TAGS) \
		--template-file test/templates/$*.yaml \
		--capabilities CAPABILITY_NAMED_IAM \
		--parameter-overrides StackNamePrefix=$(STACK_NAME_PREFIX) \
		$(EXTRA_ARGS)

delete-%:
	$(AWS_CMD) cloudformation delete-stack \
		--stack-name $(STACK_NAME_PREFIX)-$*

# Concrete deploy and delete targets for autocompletion
$(addprefix deploy-,$(basename $(notdir $(wildcard test/templates/*.yaml)))):
$(addprefix delete-,$(basename $(notdir $(wildcard test/templates/*.yaml)))):