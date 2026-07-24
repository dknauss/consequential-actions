<?php
/**
 * Contract tests for ConsequentialActions\actions() — the Layer 1 registry.
 *
 * The registry's public value is its metadata shape: a core Actions API would
 * register the same fields. These assertions fail loudly if a built-in entry
 * loses or mistypes a field, or drifts from its expected capability/consequence
 * class — a gap the triggered_actions() tests miss because they only read IDs.
 */

namespace ConsequentialActions\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use PHPUnit\Framework\TestCase;

use function ConsequentialActions\actions;

final class RegistryContractTest extends TestCase {

	protected function setUp() : void {
		parent::setUp();
		Monkey\setUp();
		Functions\when( '__' )->returnArg( 1 );
		Functions\when( 'apply_filters' )->returnArg( 2 );
	}

	protected function tearDown() : void {
		Monkey\tearDown();
		parent::tearDown();
	}

	/** The allowed consequence classes, per the actions() docblock. */
	private const CONSEQUENCE_CLASSES = array(
		'privilege-escalation',
		'account-takeover',
		'code-execution',
		'destructive',
	);

	/** Expected capability + consequence class per built-in action ID. */
	private function expected() : array {
		return array(
			'core/change-own-password'  => array( 'caps' => array( 'edit_user' ), 'class' => 'account-takeover' ),
			'core/change-own-email'     => array( 'caps' => array( 'edit_user' ), 'class' => 'account-takeover' ),
			'core/change-user-password' => array( 'caps' => array( 'edit_user' ), 'class' => 'account-takeover' ),
			'core/change-user-email'    => array( 'caps' => array( 'edit_user' ), 'class' => 'account-takeover' ),
			'core/create-user'          => array( 'caps' => array( 'create_users' ), 'class' => 'privilege-escalation' ),
			'core/promote-user'         => array( 'caps' => array( 'promote_users' ), 'class' => 'privilege-escalation' ),
		);
	}

	public function testCatalogContainsExactlyTheExpectedIds() : void {
		$this->assertSame(
			array_keys( $this->expected() ),
			array_keys( actions() ),
			'The built-in catalog IDs (or their order) drifted from the expected set.'
		);
	}

	public function testEveryBuiltinEntryHasCompleteMetadataShape() : void {
		foreach ( actions() as $id => $meta ) {
			$this->assertIsString( $meta['label'] ?? null, "$id: label must be a string" );
			$this->assertNotSame( '', $meta['label'], "$id: label must be non-empty" );

			$this->assertIsArray( $meta['capabilities'] ?? null, "$id: capabilities must be an array" );
			$this->assertNotEmpty( $meta['capabilities'], "$id: capabilities must be non-empty" );
			foreach ( $meta['capabilities'] as $cap ) {
				$this->assertIsString( $cap, "$id: each capability must be a string" );
			}

			$this->assertIsString( $meta['category'] ?? null, "$id: category must be a string" );

			$this->assertContains(
				$meta['consequence_class'] ?? null,
				self::CONSEQUENCE_CLASSES,
				"$id: consequence_class must be one of the allowed classes"
			);

			$this->assertIsString( $meta['scope'] ?? null, "$id: scope must be a string" );

			$this->assertIsArray( $meta['annotations'] ?? null, "$id: annotations must be an array" );
			$this->assertIsBool( $meta['annotations']['destructive'] ?? null, "$id: annotations.destructive must be a bool" );
			$this->assertIsBool( $meta['annotations']['requires_recent_auth'] ?? null, "$id: annotations.requires_recent_auth must be a bool" );
		}
	}

	public function testExpectedCapabilitiesAndConsequenceClasses() : void {
		$actions = actions();
		foreach ( $this->expected() as $id => $want ) {
			$this->assertSame( $want['caps'], $actions[ $id ]['capabilities'], "$id: capabilities mismatch" );
			$this->assertSame( $want['class'], $actions[ $id ]['consequence_class'], "$id: consequence_class mismatch" );
		}
	}

	public function testAllBuiltinsAreNonDestructiveAndRequireRecentAuth() : void {
		foreach ( actions() as $id => $meta ) {
			$this->assertSame( 'user-management', $meta['category'], "$id: unexpected category" );
			$this->assertSame( 'users', $meta['scope'], "$id: unexpected scope" );
			$this->assertFalse( $meta['annotations']['destructive'], "$id: expected non-destructive" );
			$this->assertTrue( $meta['annotations']['requires_recent_auth'], "$id: expected requires_recent_auth" );
		}
	}

	/**
	 * The consequential_actions filter may still add a label-only entry — the
	 * consumers read only the ID (array_keys) and label, so a filter that predates
	 * the richer shape must keep working.
	 */
	public function testFilterCanStillAddLabelOnlyEntry() : void {
		Functions\when( 'apply_filters' )->alias(
			static function ( $hook, $value ) {
				if ( 'consequential_actions' === $hook ) {
					$value['x/custom'] = array( 'label' => 'Custom label-only action' );
				}
				return $value;
			}
		);

		$actions = actions();
		$this->assertArrayHasKey( 'x/custom', $actions, 'A label-only filtered entry must be accepted.' );
		$this->assertSame( 'Custom label-only action', $actions['x/custom']['label'] );
		// Built-ins still present and intact alongside the filtered entry.
		$this->assertArrayHasKey( 'core/promote-user', $actions );
	}
}
