from __future__ import print_function

import argparse
import os.path

import ssg.build_profile
import ssg.build_remediations as remediation
import ssg.build_yaml
import ssg.jinja
import ssg.utils
import ssg.controls
import ssg.products
import ssg.environment
import ssg.templates
from ssg.build_cpe import ProductCPEs
from ssg.constants import BENCHMARKS
from ssg.entities.profile import ProfileWithInlinePolicies


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--build-config-yaml", required=True,
        help="YAML file with information about the build configuration. "
        "e.g.: ~/scap-security-guide/build/build_config.yml "
        "needed for autodetection of profile root"
    )
    parser.add_argument(
        "--product-yaml", required=True,
        help="YAML file with information about the product we are building. "
        "e.g.: ~/scap-security-guide/products/rhel9/product.yml "
        "needed for autodetection of profile root"
    )
    parser.add_argument(
        "--resolved-base", required=True,
        help="To which directory to put processed rule/group/value YAMLs.")
    parser.add_argument(
        "--project-root",
        help="Path to the repository ie. project root "
        "e.g.: ~/scap-security-guide/",
    )
    parser.add_argument(
        "--sce-metadata",
        help="Combined SCE metadata to read."
    )
    parser.add_argument(
        "--stig-references", help="DISA STIG Reference XCCDF file"
    )
    parser.add_argument(
        "--rule-id",
        type=str,
        default="off",
        help="Creates a profile with the specified rule and does not use other profiles."
        "The profile ID is identical to the rule ID of the selected rule."
        " If you want to process all rules in benchmark of the product, "
        "you can use 'ALL_RULES'.",
    )
    parser.add_argument(
        "--templates-dir", required=True,
        help="Path to directory which contains content templates. "
        "e.g.: ~/scap-security-guide/shared/templates"
    )
    parser.add_argument(
        "--remediation-type", required=True, action="append",
        help="language or type of the remediations we are combining."
        "example: ansible")
    return parser


def get_env_yaml(build_config_yaml, product_yaml):
    if build_config_yaml is None or product_yaml is None:
        return None

    env_yaml = ssg.environment.open_environment(build_config_yaml, product_yaml)
    return env_yaml


def get_all_content_directories(env_yaml, product_yaml):
    relative_benchmark_root = ssg.utils.required_key(env_yaml, "benchmark_root")
    benchmark_root = os.path.join(product_yaml["product_dir"], relative_benchmark_root)

    add_content_dirs = get_additional_content_directories(env_yaml)
    return [benchmark_root] + add_content_dirs


def get_additional_content_directories(env_yaml):
    # we assume that the project root is one directory above build-scripts
    project_root = os.path.dirname(os.path.dirname(__file__))
    additional_content_directories = env_yaml.get("additional_content_directories", [])

    absolute_additional_content_dirs = []
    for dirname in additional_content_directories:
        if not os.path.isabs(dirname):
            dirname = os.path.join(project_root, dirname)
        absolute_additional_content_dirs.append(dirname)
    return absolute_additional_content_dirs


def load_benchmark_source_data_from_directory_tree(loader, env_yaml, product_yaml):
    relevant_benchmark_sources = get_all_content_directories(env_yaml, product_yaml)
    loader.process_directory_trees(relevant_benchmark_sources)


def dump_compiled_profile(base_dir, profile):
    dest = os.path.join(base_dir, "profiles", "{name}.profile".format(name=profile.id_))
    profile.dump_json(dest)


def get_all_resolved_profiles_by_id(
        env_yaml, product_yaml, loader, product_cpes, controls_manager, controls_dir=None):
    profile_files = ssg.products.get_profile_files_from_root(env_yaml, product_yaml)
    profiles_by_id = load_resolve_and_validate_profiles(
        env_yaml, profile_files, loader, controls_manager, product_cpes)
    return profiles_by_id


def load_resolve_and_validate_profiles(
        env_yaml, profile_files, loader, controls_manager, product_cpes
        ):
    profiles_by_id = ssg.build_profile.make_name_to_profile_mapping(
        profile_files, env_yaml, product_cpes
    )

    for p in profiles_by_id.values():
        p.resolve(profiles_by_id, loader.all_rules, controls_manager)

        p.validate_variables(loader.all_values.values())
        p.validate_rules(loader.all_rules.values(), loader.all_groups.values())
        p.validate_refine_rules(loader.all_rules.values())
    return profiles_by_id


def save_everything(base_dir, loader, controls_manager, profiles):
    controls_manager.save_everything(os.path.join(base_dir, "controls"))
    loader.save_all_entities(base_dir)
    if not os.path.exists(os.path.join(base_dir, "profiles")):
        os.makedirs(os.path.join(base_dir, "profiles"))
    for p in profiles:
        dump_compiled_profile(base_dir, p)


def find_existing_rules(project_root, relevant_benchmarks=None):
    rules = set()
    if relevant_benchmarks is None:
        relevant_benchmarks = BENCHMARKS
    for benchmark in relevant_benchmarks:
        benchmark = os.path.join(project_root, benchmark)
        for dirpath, _, filenames in os.walk(benchmark):
            if "rule.yml" in filenames:
                rule_id = os.path.basename(dirpath)
                rules.add(rule_id)
    return rules


def add_stig_references(stig_reference_path, all_rules):
    if not stig_reference_path:
        return
    stig_references = ssg.build_stig.map_versions_to_rule_ids(stig_reference_path)
    for rule in all_rules:
        rule.add_stig_references(stig_references)


def get_relevant_benchmarks(env_yaml, product_yaml):
    benchmark_paths = get_all_content_directories(env_yaml, product_yaml)
    out = set()
    for benchmark in BENCHMARKS:
        for path in benchmark_paths:
            if benchmark in os.path.normpath(path):
                out.add(benchmark)
    return out


def get_minimal_profiles_by_id(rules):
    out = {}
    for rule in rules:
        data = {
              'documentation_complete': True,
              'single_rule_profile': True,
              'variables': {},
              'selected': [rule],
              'id_': rule,
        }
        profile = ProfileWithInlinePolicies.get_instance_from_full_dict(data)
        out[profile.id_] = profile
    return out


def get_profiles_per_rule_by_id(rule_id, project_root_abspath, env_yaml, product_yaml):
    relevant_benchmarks = get_relevant_benchmarks(env_yaml, product_yaml)
    rules = find_existing_rules(project_root_abspath, relevant_benchmarks)
    if rule_id not in rules and "ALL_RULES" not in rule_id:
        raise Exception("Rule ID: {} not found!".format(rule_id))
    if "ALL_RULES" not in rule_id:
        rules = {rule_id}
    return get_minimal_profiles_by_id(rules)


def build_templated_content(env_yaml, resolved_base, templates_dir, rules, platforms):
    resolved_rules_dir = os.path.join(resolved_base, "rules")
    remediations_dir = os.path.join(resolved_base, "fixes_from_templates")
    checks_dir = os.path.join(resolved_base, "checks_from_templates")
    platforms_dir = os.path.join(resolved_base, "platforms")
    cpe_items_dir = os.path.join(resolved_base, "cpe_items")
    builder = ssg.templates.Builder(
        env_yaml, resolved_rules_dir, templates_dir,
        remediations_dir, checks_dir, platforms_dir, cpe_items_dir)
    builder.rules = rules
    builder.platforms = platforms
    builder.build()


def prepare_output_dirs(output_dir, remediation_types):
    output_dirs = dict()
    for lang in remediation_types:
        language_output_dir = os.path.join(output_dir, lang)
        ssg.utils.mkdir_p(language_output_dir)
        output_dirs[lang] = language_output_dir
    return output_dirs


def find_remediation(
        fixes_from_templates_dir, rule_dir, lang, product, expected_file_name):
    language_fixes_from_templates_dir = os.path.join(
        fixes_from_templates_dir, lang)
    fix_path = None
    # first look for a static remediation
    rule_dir_remediations = remediation.get_rule_dir_remediations(
        rule_dir, lang, product)
    if len(rule_dir_remediations) > 0:
        # first item in the list has the highest priority
        fix_path = rule_dir_remediations[0]
    if fix_path is None:
        # check if we have a templated remediation instead
        if os.path.isdir(language_fixes_from_templates_dir):
            templated_fix_path = os.path.join(
                language_fixes_from_templates_dir, expected_file_name)
            if os.path.exists(templated_fix_path):
                fix_path = templated_fix_path
    return fix_path


def process_remediation(
        rule, fix_path, lang, output_dirs, expected_file_name, env_yaml, cpe_platforms):
    remediation_cls = remediation.REMEDIATION_TO_CLASS[lang]
    remediation_obj = remediation_cls(fix_path)
    remediation_obj.associate_rule(rule)
    fix = remediation.process(remediation_obj, env_yaml, cpe_platforms)
    if fix:
        output_file_path = os.path.join(output_dirs[lang], expected_file_name)
        remediation.write_fix_to_file(fix, output_file_path)


def process_remediations_for_rule(
        rule, langs, fixes_from_templates_dir, product, output_dirs,
        env_yaml, cpe_platforms):
    rule_dir = os.path.dirname(rule.definition_location)
    for lang in langs:
        ext = remediation.REMEDIATION_TO_EXT_MAP[lang]
        expected_file_name = rule.id_ + ext
        fix_path = find_remediation(
            fixes_from_templates_dir, rule_dir, lang, product,
            expected_file_name)
        if fix_path is None:
            # neither static nor templated remediation found
            continue
        try:
            process_remediation(
                rule, fix_path, lang, output_dirs, expected_file_name, env_yaml, cpe_platforms)
        except Exception as exc:
            msg = (
                "Failed to dispatch {lang} remediation for {rule_id}: {error}"
                .format(lang=lang, rule_id=rule.id_, error=str(exc)))
            raise RuntimeError(msg)


def process_remediations(env_yaml, remediation_type, resolved_base, rules, cpe_platforms):
    output_dir = os.path.join(resolved_base, "fixes")
    fixes_from_templates_dir = os.path.join(resolved_base, "fixes_from_templates")
    product = ssg.utils.required_key(env_yaml, "product")
    output_dirs = prepare_output_dirs(output_dir, remediation_type)
    for rule in rules:
        process_remediations_for_rule(
            rule, remediation_type, fixes_from_templates_dir,
            product, output_dirs, env_yaml, cpe_platforms)


def main():
    parser = create_parser()
    args = parser.parse_args()

    project_root_abspath = os.path.abspath(args.project_root)

    env_yaml = get_env_yaml(args.build_config_yaml, args.product_yaml)
    ssg.jinja.initialize(env_yaml)
    product_yaml = ssg.products.Product(args.product_yaml)

    product_cpes = ProductCPEs()
    product_cpes.load_product_cpes(env_yaml)

    # Rules in the same benchmark_root might have a product CPE set as
    # a platform and could be shared between all the products.
    # TODO: This is a hackish feature of 'ocp4' and 'eks' products
    #       we should fix that as it brings implicit dependency between
    #       products with shared guide directory
    for extra_product_yaml in ssg.products.get_all_products_with_same_guide_directory(
                                           project_root_abspath, product_yaml):
        product_cpes.load_cpes_from_list(extra_product_yaml.get("cpes", []))
    product_cpes.load_content_cpes(env_yaml)

    loader = ssg.build_yaml.BuildLoader(
        None, env_yaml, product_cpes, args.sce_metadata)
    loader.load_components()
    load_benchmark_source_data_from_directory_tree(loader, env_yaml, product_yaml)

    controls_dir = os.path.join(project_root_abspath, "controls")

    existing_rules = find_existing_rules(project_root_abspath)

    controls_manager = ssg.controls.ControlsManager(
        controls_dir, env_yaml, existing_rules)
    controls_manager.load()
    controls_manager.remove_selections_not_known(loader.all_rules)
    controls_manager.add_references(loader.all_rules)

    add_stig_references(args.stig_references, loader.all_rules.values())

    if args.rule_id == "ALL_RULES" or args.rule_id == "off":
        normal_profiles = get_all_resolved_profiles_by_id(
            env_yaml, product_yaml, loader, product_cpes, controls_manager, controls_dir
        )
    else:
        normal_profiles = {}
    if args.rule_id == "ALL_RULES" or args.rule_id != "off":
        single_rule_profiles = get_profiles_per_rule_by_id(
            args.rule_id, project_root_abspath, env_yaml, product_yaml
        )
    else:
        single_rule_profiles = {}
    profiles = list(normal_profiles.values()) + list(single_rule_profiles.values())
    save_everything(
        args.resolved_base, loader, controls_manager, profiles)
    build_templated_content(
        env_yaml, args.resolved_base, args.templates_dir,
        loader.all_rules.values(), product_cpes.platforms.values())
    process_remediations(
        env_yaml, args.remediation_type, args.resolved_base,
        loader.all_rules.values(), product_cpes.platforms)


if __name__ == "__main__":
    main()
